#include <wavex/Base/Logger.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

namespace wavex::base {
    namespace {
        void format_timestamp(const std::chrono::system_clock::time_point now, std::string &out) {
            using namespace std::chrono;
            const auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count();
            const auto sec = static_cast<std::time_t>(ms / 1000);
            auto millis = static_cast<int>(ms % 1000);
            if (millis < 0) millis += 1000;

            std::tm tm_buf{};
#if defined(_WIN32)
            gmtime_s(&tm_buf, &sec);
#else
            gmtime_r(&sec, &tm_buf);
#endif

            char buf[32];
            std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                          tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
                          tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, millis);
            out.append(buf);
        }

        void populate_thread_id(LogBuffer *slot) {
            static_assert(sizeof(LogBuffer::thread_id_buf) >= 20, "thread_id_buf must hold a 20-digit uint64_t");
            constexpr size_t thread_ip_buf_size = sizeof(LogBuffer::thread_id_buf);
            thread_local auto [tid_buff, tid_len] = [] {
                struct {
                    char data[thread_ip_buf_size];
                    uint8_t len;
                } cache{};
                const auto numeric_id = std::hash<std::thread::id>{}(std::this_thread::get_id());
                if (auto [ptr, ec] = std::to_chars(cache.data, cache.data + thread_ip_buf_size, numeric_id);
                    ec == std::errc{}) {
                    cache.len = static_cast<uint8_t>(ptr - cache.data);
                } else {
                    cache.data[0] = '?'; // defensive; unreachable with >= 20
                    cache.len = 1;
                }
                return cache;
            }();
            std::memcpy(slot->thread_id_buf, tid_buff, tid_len);
            slot->thread_id_len = tid_len;
        }
    } // anonymous namespace

    // ─── BufferPool Implementation ───────────────────────────────────────────
    struct Logger::BufferPool {
        std::vector<std::unique_ptr<LogBuffer>> storage_{};
        std::vector<LogBuffer *> free_list_{};
        std::mutex mutex_{};
        std::condition_variable cv_space_{};
        size_t capacity_{0};
        size_t max_capacity_{0};

        BufferPool(const size_t initial_cap, const size_t max_cap)
            : capacity_(std::max<size_t>(16, initial_cap)),
              max_capacity_(std::max<size_t>(std::max<size_t>(16, initial_cap), max_cap)) {
            storage_.reserve(max_capacity_);
            free_list_.reserve(max_capacity_);
            for (size_t i = 0; i < capacity_; ++i) {
                storage_.push_back(std::make_unique<LogBuffer>());
                free_list_.push_back(storage_.back().get());
            }
        }

        size_t free_count() {
            std::lock_guard lock(mutex_);
            return free_list_.size();
        }

        LogBuffer *acquire() {
            std::lock_guard lock(mutex_);
            if (free_list_.empty()) return nullptr;
            LogBuffer *b = free_list_.back();
            free_list_.pop_back();
            return b;
        }

        LogBuffer *acquire_blocking() {
            std::unique_lock lock(mutex_);
            cv_space_.wait(lock, [this] { return !free_list_.empty(); });
            LogBuffer *b = free_list_.back();
            free_list_.pop_back();
            return b;
        }

        LogBuffer *grow() {
            std::lock_guard lock(mutex_);
            if (storage_.size() >= max_capacity_) {
                return nullptr;
            }
            const size_t batch = std::min<size_t>(64, max_capacity_ - storage_.size());
            for (size_t i = 0; i < batch; ++i) {
                storage_.push_back(std::make_unique<LogBuffer>());
                free_list_.push_back(storage_.back().get());
            }
            capacity_ = storage_.size();
            LogBuffer *b = free_list_.back();
            free_list_.pop_back();
            return b;
        }

        void release(LogBuffer *slot) {
            if (!slot) return;
            slot->clear();
            std::lock_guard lock(mutex_);
            free_list_.push_back(slot);
            cv_space_.notify_one();
        }

        void release_batch(LogBuffer **batch, const size_t n) {
            if (!batch || n == 0) return;
            for (size_t i = 0; i < n; ++i) {
                if (batch[i]) {
                    batch[i]->clear();
                }
            }
            std::lock_guard lock(mutex_);
            for (size_t i = 0; i < n; ++i) {
                if (batch[i]) {
                    free_list_.push_back(batch[i]);
                }
            }
            cv_space_.notify_all();
        }
    };

    // ─── AsyncQueue Implementation ───────────────────────────────────────────
    struct Logger::AsyncQueue {
        std::vector<LogBuffer *> ring_{};
        std::atomic<size_t> count_{0};
        size_t capacity_{0};
        size_t max_capacity_{0};
        size_t head_{0};
        size_t tail_{0};
        std::mutex mutex_{};
        std::condition_variable cv_not_empty_{};
        std::condition_variable cv_not_full_{};
        bool shutdown_{false};
        // Both guarded by mutex_. They let producers/consumer skip notify syscalls when nobody sleeps:
        // with a worker that is busy draining (the common case under load) a notify per record is pure
        // overhead. Because the flags are read and written under mutex_, no wakeup can be lost.
        bool consumer_waiting_{false};
        size_t producers_waiting_{0};

        AsyncQueue(const size_t initial_cap, const size_t max_cap)
            : ring_(std::max<size_t>(16, initial_cap), nullptr),
              capacity_(std::max<size_t>(16, initial_cap)),
              max_capacity_(std::max<size_t>(std::max<size_t>(16, initial_cap), max_cap)) {
        }

        [[nodiscard]] size_t size() const noexcept {
            return count_.load(std::memory_order_relaxed);
        }

        [[nodiscard]] size_t capacity() const noexcept {
            return capacity_;
        }

        bool push(LogBuffer *slot, const LogLevel lvl, const OverflowPolicy policy) {
            std::unique_lock lock(mutex_);
            const size_t soft_cap = (capacity_ * 9) / 10;
            const bool is_priority = (lvl >= LogLevel::WARN);

            if (policy == OverflowPolicy::Block) {
                ++producers_waiting_;
                cv_not_full_.wait(lock, [this, is_priority, soft_cap] {
                    if (shutdown_) return true;
                    return is_priority
                               ? (count_.load(std::memory_order_relaxed) < capacity_)
                               : (count_.load(std::memory_order_relaxed) < soft_cap);
                });
                --producers_waiting_;
                if (shutdown_) return false;
            } else if (policy == OverflowPolicy::Drop) {
                const size_t cur = count_.load(std::memory_order_relaxed);
                if (is_priority) {
                    if (cur >= capacity_) return false;
                } else {
                    if (cur >= soft_cap) return false;
                }
            } else if (policy == OverflowPolicy::Grow) {
                if (count_.load(std::memory_order_relaxed) >= capacity_) {
                    if (capacity_ < max_capacity_) {
                        grow_locked();
                    } else {
                        return false;
                    }
                }
            }

            ring_[tail_] = slot;
            tail_ = (tail_ + 1) % capacity_;
            count_.fetch_add(1, std::memory_order_relaxed);
            const bool wake_consumer = consumer_waiting_;
            lock.unlock();
            if (wake_consumer) cv_not_empty_.notify_one();
            return true;
        }

        size_t pop_batch(LogBuffer **out_batch, const size_t max_batch, const std::chrono::milliseconds wait_timeout) {
            std::unique_lock lock(mutex_);
            if (count_.load(std::memory_order_relaxed) == 0 && !shutdown_) {
                consumer_waiting_ = true;
                cv_not_empty_.wait_for(lock, wait_timeout, [this] {
                    return count_.load(std::memory_order_relaxed) > 0 || shutdown_;
                });
                consumer_waiting_ = false;
            }
            if (count_.load(std::memory_order_relaxed) == 0) return 0;

            size_t n = 0;
            while (n < max_batch && count_.load(std::memory_order_relaxed) > 0) {
                out_batch[n++] = ring_[head_];
                head_ = (head_ + 1) % capacity_;
                count_.fetch_sub(1, std::memory_order_relaxed);
            }
            if (producers_waiting_ != 0) cv_not_full_.notify_all();
            return n;
        }

        void shutdown() {
            {
                std::lock_guard lock(mutex_);
                shutdown_ = true;
            }
            cv_not_empty_.notify_all();
            cv_not_full_.notify_all();
        }

    private:
        void grow_locked() {
            const size_t new_cap = std::min(capacity_ * 2, max_capacity_);
            if (new_cap <= capacity_) return;
            std::vector<LogBuffer *> new_ring(new_cap, nullptr);
            const size_t cur_cnt = count_.load(std::memory_order_relaxed);
            for (size_t i = 0; i < cur_cnt; ++i) {
                new_ring[i] = ring_[(head_ + i) % capacity_];
            }
            ring_ = std::move(new_ring);
            head_ = 0;
            tail_ = cur_cnt % new_cap;
            capacity_ = new_cap;
        }
    };

    // ─── Logger Lifecycle ────────────────────────────────────────────────────
    Logger::Logger()
        : pool_capacity_(4096),
          max_pool_capacity_(16384),
          dropped_count_(0),
          submitted_count_(0),
          processed_count_(0),
          flush_interval_ms_(50),
          pool_(std::make_unique<BufferPool>(pool_capacity_, max_pool_capacity_)),
          queue_(std::make_unique<AsyncQueue>(pool_capacity_, max_pool_capacity_)),
          sink_(&std::cerr),
          min_level_(LogLevel::INFO),
          overflow_policy_(OverflowPolicy::Drop),
          colored_(true),
          async_mode_(true),
          explicit_async_(false),
          custom_stream_(false),
          running_(false) {
        start_worker();
    }

    Logger::~Logger() {
        shutdown();
    }

    Logger &Logger::instance() {
        static Logger inst;
        return inst;
    }

    void Logger::configure(const LoggerConfig &config) {
        flush();
        shutdown();

        pool_capacity_ = config.pool_capacity;
        max_pool_capacity_ = config.max_pool_capacity;
        flush_interval_ms_.store(config.flush_interval.count(), std::memory_order_relaxed);
        overflow_policy_ = config.overflow_policy;
        async_mode_ = config.async_mode;
        explicit_async_ = true;

        pool_ = std::make_unique<BufferPool>(pool_capacity_, max_pool_capacity_);
        queue_ = std::make_unique<AsyncQueue>(pool_capacity_, max_pool_capacity_);
        dropped_count_.store(0, std::memory_order_relaxed);
        submitted_count_.store(0, std::memory_order_relaxed);
        processed_count_.store(0, std::memory_order_relaxed);

        if (async_mode_) {
            start_worker();
        }
    }

    void Logger::set_async(const bool enable) {
        explicit_async_ = true;
        if (enable == async_mode_) {
            if (enable && !running_) {
                start_worker();
            }
            return;
        }
        if (enable) {
            async_mode_ = true;
            if (!running_) {
                start_worker();
            }
        } else {
            flush();
            shutdown();
            async_mode_ = false;
        }
    }

    void Logger::set_output(std::ostream &os) {
        flush();
        std::lock_guard lock(mutex_);
        file_sink_.reset();
        sink_ = &os;
        custom_stream_ = (&os != &std::cerr && &os != &std::cout);
    }

    void Logger::set_output(const std::string &path) {
        flush();
        std::lock_guard lock(mutex_);
        utils::BinaryFile::write_all(path, "", true);
        file_sink_.emplace(path, utils::FileMode::Append);
        if (file_sink_->is_open()) {
            sink_ = nullptr;
        }
        custom_stream_ = false;
    }

    void Logger::flush() {
        if (is_sync_path()) {
            std::lock_guard lock(mutex_);
            if (file_sink_.has_value() && file_sink_->is_open()) {
                std::ignore = file_sink_->flush();
            } else if (sink_) {
                sink_->flush();
            }
            return;
        }

        const uint64_t target = submitted_count_.load(std::memory_order_acquire);
        std::unique_lock lock(flush_mutex_);
        cv_flush_.wait(lock, [this, target] {
            return processed_count_.load(std::memory_order_acquire) >= target || !running_;
        });

        std::lock_guard sink_lock(mutex_);
        if (file_sink_.has_value() && file_sink_->is_open()) {
            std::ignore = file_sink_->flush();
        } else if (sink_) {
            sink_->flush();
        }
    }

    void Logger::shutdown() {
        if (!running_) return;
        running_ = false;
        if (queue_) {
            queue_->shutdown();
        }
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
        std::lock_guard lock(mutex_);
        if (file_sink_.has_value() && file_sink_->is_open()) {
            std::ignore = file_sink_->flush();
        } else if (sink_) {
            sink_->flush();
        }
    }

    std::string_view Logger::extract_filename(const std::string_view filepath) {
        const auto pos = filepath.find_last_of("/\\");
        return (pos == std::string_view::npos) ? filepath : filepath.substr(pos + 1);
    }

    void Logger::populate_header(LogBuffer *slot, const LogLevel lvl, const std::source_location &loc) {
        slot->clear();
        slot->timestamp = std::chrono::system_clock::now();
        slot->level = lvl;
        slot->has_location = true;
        slot->line = loc.line();
        populate_thread_id(slot);

        const std::string_view filename = extract_filename(loc.file_name());
        const size_t copy_len = std::min(filename.size(), sizeof(slot->filename_buf) - 1);
        std::memcpy(slot->filename_buf, filename.data(), copy_len);
        slot->filename_buf[copy_len] = '\0';
    }

    void Logger::populate_header_no_loc(LogBuffer *slot, const LogLevel lvl) {
        slot->clear();
        slot->timestamp = std::chrono::system_clock::now();
        slot->level = lvl;
        slot->has_location = false;
        slot->line = 0;
        slot->filename_buf[0] = '\0';
        populate_thread_id(slot);
    }

    LogBuffer *Logger::acquire_buffer(const LogLevel lvl) {
        if (!pool_ || !queue_) return nullptr;

        const size_t q_capacity = queue_->capacity();
        const size_t soft_cap = (q_capacity * 9) / 10;
        const size_t current_q_size = queue_->size();

        // Keep (capacity - soft_cap) pool slots in reserve for WARN+ even when the worker has already
        // popped records from the queue but not yet returned their buffers to the pool.
        const size_t reserve = q_capacity - soft_cap;
        const bool is_priority = (lvl >= LogLevel::WARN);
        if (!is_priority && (current_q_size >= soft_cap ||
                             (overflow_policy_ == OverflowPolicy::Drop && pool_->free_count() <= reserve))) {
            if (overflow_policy_ == OverflowPolicy::Drop) {
                dropped_count_.fetch_add(1, std::memory_order_relaxed);
                return nullptr;
            }
        }

        if (current_q_size >= q_capacity) {
            if (overflow_policy_ == OverflowPolicy::Drop) {
                dropped_count_.fetch_add(1, std::memory_order_relaxed);
                return nullptr;
            }
        }

        LogBuffer *slot = pool_->acquire();
        if (!slot) {
            if (overflow_policy_ == OverflowPolicy::Grow) {
                slot = pool_->grow();
                if (!slot) {
                    dropped_count_.fetch_add(1, std::memory_order_relaxed);
                    return nullptr;
                }
            } else if (overflow_policy_ == OverflowPolicy::Block) {
                slot = pool_->acquire_blocking();
                if (!slot) return nullptr;
            } else {
                dropped_count_.fetch_add(1, std::memory_order_relaxed);
                return nullptr;
            }
        }

        return slot;
    }

    void Logger::enqueue_buffer(LogBuffer *slot) {
        if (!slot) return;
        if (!queue_ || !running_) {
            std::string line;
            format_record(slot, line);
            if (pool_) {
                pool_->release(slot);
            }
            std::lock_guard lock(mutex_);
            if (file_sink_.has_value() && file_sink_->is_open()) {
                std::ignore = file_sink_->write(line);
                std::ignore = file_sink_->flush();
            } else if (sink_) {
                (*sink_) << line;
                sink_->flush();
            }
            return;
        }

        if (queue_->push(slot, slot->level, overflow_policy_)) {
            submitted_count_.fetch_add(1, std::memory_order_release);
        } else {
            pool_->release(slot);
            dropped_count_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void Logger::write_loc_sync(const LogLevel lvl, const std::source_location &loc, const std::string_view msg) {
        LogBuffer temp_slot;
        populate_header(&temp_slot, lvl, loc);
        if (msg.size() <= LogBuffer::kInlineCapacity) {
            std::memcpy(temp_slot.inline_storage, msg.data(), msg.size());
            temp_slot.length = static_cast<uint32_t>(msg.size());
        } else {
            temp_slot.fallback.assign(msg.data(), msg.size());
        }
        std::string line;
        line.reserve(128 + msg.size());
        format_record(&temp_slot, line);

        std::lock_guard lock(mutex_);
        if (file_sink_.has_value() && file_sink_->is_open()) {
            std::ignore = file_sink_->write(line);
            std::ignore = file_sink_->flush();
        } else if (sink_) {
            (*sink_) << line;
            sink_->flush();
        }
    }

    void Logger::write_sync(const LogLevel lvl, const std::string_view msg) {
        LogBuffer temp_slot;
        populate_header_no_loc(&temp_slot, lvl);
        if (msg.size() <= LogBuffer::kInlineCapacity) {
            std::memcpy(temp_slot.inline_storage, msg.data(), msg.size());
            temp_slot.length = static_cast<uint32_t>(msg.size());
        } else {
            temp_slot.fallback.assign(msg.data(), msg.size());
        }
        std::string line;
        line.reserve(96 + msg.size());
        format_record(&temp_slot, line);

        std::lock_guard lock(mutex_);
        if (file_sink_.has_value() && file_sink_->is_open()) {
            std::ignore = file_sink_->write(line);
            std::ignore = file_sink_->flush();
        } else if (sink_) {
            (*sink_) << line;
            sink_->flush();
        }
    }

    void Logger::start_worker() {
        if (running_) return;
        if (!pool_) {
            pool_ = std::make_unique<BufferPool>(pool_capacity_, max_pool_capacity_);
        }
        if (!queue_) {
            queue_ = std::make_unique<AsyncQueue>(pool_capacity_, max_pool_capacity_);
        }
        running_ = true;
        worker_thread_ = std::thread(&Logger::worker_loop, this);
    }

    void Logger::worker_loop() {
        std::array<LogBuffer *, 256> batch{};
        std::string line_buf;
        line_buf.reserve(4096);

        auto last_drop_report_time = std::chrono::steady_clock::now();
        uint64_t last_reported_drops = 0;

        while (running_) {
            const size_t n = queue_->pop_batch(batch.data(), batch.size(),
                                                   std::chrono::milliseconds(flush_interval_ms_.load(std::memory_order_relaxed)));

            // Non-silent loss notification check
            if (const uint64_t current_drops = dropped_count_.load(std::memory_order_relaxed);
                current_drops > last_reported_drops) {
                const uint64_t new_drops = current_drops - last_reported_drops;
                const auto now = std::chrono::steady_clock::now();
                const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_drop_report_time).
                        count();
                const auto elapsed_sec = std::max<int64_t>(1, elapsed);

                std::string warn_msg;
                warn_msg.reserve(128);
                if (colored_ && !file_sink_.has_value()) {
                    warn_msg.append(log_level_color(LogLevel::WARN));
                }
                warn_msg.append("[WARN ] [Logger] Dropped ");
                warn_msg.append(std::to_string(new_drops));
                warn_msg.append(" messages due to queue overflow in the last ");
                warn_msg.append(std::to_string(elapsed_sec));
                warn_msg.append("s");
                if (colored_ && !file_sink_.has_value()) {
                    warn_msg.append(ansi_reset);
                }
                warn_msg.push_back('\n'); {
                    std::lock_guard lock(mutex_);
                    if (file_sink_.has_value() && file_sink_->is_open()) {
                        std::ignore = file_sink_->write(warn_msg);
                    } else if (sink_) {
                        (*sink_) << warn_msg;
                    }
                }

                last_reported_drops = current_drops;
                last_drop_report_time = now;
            }

            if (n > 0) {
                line_buf.clear();
                for (size_t i = 0; i < n; ++i) {
                    format_record(batch[i], line_buf);
                } {
                    std::lock_guard lock(mutex_);
                    if (file_sink_.has_value() && file_sink_->is_open()) {
                        std::ignore = file_sink_->write(line_buf);
                    } else if (sink_) {
                        (*sink_) << line_buf;
                    }
                }

                pool_->release_batch(batch.data(), n);
                processed_count_.fetch_add(n, std::memory_order_release);
                notify_flush_waiters();
            } else {
                std::lock_guard lock(mutex_);
                if (file_sink_.has_value() && file_sink_->is_open()) {
                    std::ignore = file_sink_->flush();
                } else if (sink_) {
                    sink_->flush();
                }
            }
        }

        // Drain any remaining items after shutdown
        while (true) {
            const size_t n = queue_->pop_batch(batch.data(), batch.size(), std::chrono::milliseconds(0));
            if (n == 0) break;
            line_buf.clear();
            for (size_t i = 0; i < n; ++i) {
                format_record(batch[i], line_buf);
            } {
                std::lock_guard lock(mutex_);
                if (file_sink_.has_value() && file_sink_->is_open()) {
                    std::ignore = file_sink_->write(line_buf);
                    std::ignore = file_sink_->flush();
                } else if (sink_) {
                    (*sink_) << line_buf;
                    sink_->flush();
                }
            }
            pool_->release_batch(batch.data(), n);
            processed_count_.fetch_add(n, std::memory_order_release);
            notify_flush_waiters();
        }
    }

    // flush() tests processed_count_ under flush_mutex_ and then sleeps. Taking the mutex here (even though
    // nothing is written under it) orders this notify after the waiter is either asleep or has seen the new
    // count, so the wakeup cannot fall between its predicate check and its wait.
    void Logger::notify_flush_waiters() {
        { std::lock_guard flush_lock(flush_mutex_); }
        cv_flush_.notify_all();
    }

    void Logger::format_record(const LogBuffer *slot, std::string &line) const {
        if (colored_ && !file_sink_.has_value()) {
            line.append(log_level_color(slot->level));
        }
        line.push_back('[');
        format_timestamp(slot->timestamp, line);
        line.append("] [");
        line.append(log_level_tag(slot->level));
        line.append("] [tid:");
        if (slot->thread_id_len > 0) {
            line.append(slot->thread_id_buf, slot->thread_id_len);
        }
        line.push_back(']');
        if (slot->has_location) {
            line.append(" [");
            line.append(slot->filename_view());
            line.push_back(':');
            char line_num_buf[16];
            const auto [ptr, _] = std::to_chars(line_num_buf, line_num_buf + 16, slot->line);
            line.append(line_num_buf, static_cast<size_t>(ptr - line_num_buf));
            line.push_back(']');
        }
        line.push_back(' ');
        line.append(slot->message_view());

        if (colored_ && !file_sink_.has_value()) {
            line.append(ansi_reset);
        }
        line.push_back('\n');
    }
} // namespace wavex::base
