// Copyright (c) 2026 Jyotipriya Mondal
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
/**
 * @file Cli.hpp
 * @brief Built-in Command Line Interface (CLI) argument parser for WaveX applications.
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <algorithm>

namespace wavex::cli {
    /**
     * @enum OptionType
     * @brief Type of CLI option.
     */
    enum class OptionType {
        Flag, ///< Boolean flag (e.g. --verbose, -v)
        Value, ///< Value option (e.g. --port 8080, --host 127.0.0.1)
        Positional ///< Positional argument
    };

    /**
     * @struct Option
     * @brief Definition and state of a CLI option/flag.
     */
    struct Option {
        std::string name; ///< Long option name (e.g. "port")
        std::string description; ///< Help description
        std::string default_value; ///< Default value string
        std::string value; ///< Parsed string value
        OptionType type{OptionType::Value}; ///< Enum type
        char short_name{'\0'}; ///< Short option character (e.g. 'p')
        bool required{false}; ///< Indicates if required
        bool specified{false}; ///< Indicates if specified in command line
    };

    /**
     * @struct ParseResult
     * @brief Result of command line parsing.
     */
    struct ParseResult {
        std::string error_message;
        bool success{true};
        bool help_requested{false};

        [[nodiscard]] bool ok() const { return success && !help_requested; }
    };

    /**
     * @class CliParser
     * @brief High-performance, zero-dependency CLI argument parser for WaveX.
     */
    class CliParser {
    public:
        explicit CliParser(std::string program_name = "", std::string description = "")
            : program_name_(std::move(program_name)), description_(std::move(description)) {
            // Auto-register built-in help flag
            add_flag("help", 'h', "Display this help message and exit");
        }

        /// Set program name
        CliParser &set_program_name(std::string name) {
            program_name_ = std::move(name);
            return *this;
        }

        /// Set program description
        CliParser &set_description(std::string desc) {
            description_ = std::move(desc);
            return *this;
        }

        /**
         * @brief Add a boolean flag option (e.g., --verbose or -v).
         */
        CliParser &add_flag(std::string name, char short_name, std::string description) {
            Option opt;
            opt.name = std::move(name);
            opt.short_name = short_name;
            opt.description = std::move(description);
            opt.type = OptionType::Flag;
            opt.default_value = "false";
            opt.value = "false";
            register_option(std::move(opt));
            return *this;
        }

        CliParser &add_flag(std::string name, std::string description) {
            return add_flag(std::move(name), '\0', std::move(description));
        }

        /**
         * @brief Add a key-value option (e.g., --port 8080 or -p 8080).
         */
        CliParser &add_option(std::string name, char short_name, std::string description,
                              std::string default_value = "", bool required = false) {
            Option opt;
            opt.name = std::move(name);
            opt.short_name = short_name;
            opt.description = std::move(description);
            opt.type = OptionType::Value;
            opt.default_value = std::move(default_value);
            opt.value = opt.default_value;
            opt.required = required;
            register_option(std::move(opt));
            return *this;
        }

        CliParser &add_option(std::string name, std::string description,
                              std::string default_value = "", bool required = false) {
            return add_option(std::move(name), '\0', std::move(description), std::move(default_value), required);
        }

        /**
         * @brief Add a positional argument.
         */
        CliParser &add_positional(std::string name, std::string description, bool required = false) {
            Option opt;
            opt.name = std::move(name);
            opt.description = std::move(description);
            opt.type = OptionType::Positional;
            opt.required = required;
            positionals_.push_back(std::move(opt));
            return *this;
        }

        /**
         * @brief Parse command line arguments from argc and argv.
         */
        ParseResult parse(int argc, const char *const argv[]) {
            if (argc > 0 && program_name_.empty()) {
                program_name_ = argv[0];
            }

            std::vector<std::string_view> args;
            if (argc > 1) {
                args.reserve(static_cast<size_t>(argc - 1));
                for (int i = 1; i < argc; ++i) {
                    args.emplace_back(argv[i]);
                }
            }

            return parse(args);
        }

        /**
         * @brief Parse command line arguments from a collection of string_views.
         */
        ParseResult parse(const std::vector<std::string_view> &args) {
            ParseResult res;
            size_t positional_idx = 0;

            for (size_t i = 0; i < args.size(); ++i) {
                std::string_view arg = args[i];

                if (arg == "--help" || arg == "-h") {
                    res.help_requested = true;
                    if (auto *opt = find_option_mut("help")) {
                        opt->specified = true;
                        opt->value = "true";
                    }
                    return res;
                }

                // Long option: --name or --name=value
                if (arg.starts_with("--")) {
                    std::string_view name_part = arg.substr(2);
                    std::string_view val_part;
                    bool has_eq = false;

                    if (auto eq_pos = name_part.find('='); eq_pos != std::string_view::npos) {
                        val_part = name_part.substr(eq_pos + 1);
                        name_part = name_part.substr(0, eq_pos);
                        has_eq = true;
                    }

                    auto *opt = find_option_mut(std::string(name_part));
                    if (!opt) {
                        res.success = false;
                        res.error_message = "Unknown option: --" + std::string(name_part);
                        return res;
                    }

                    opt->specified = true;
                    if (opt->type == OptionType::Flag) {
                        opt->value = has_eq ? std::string(val_part) : "true";
                    } else {
                        if (has_eq) {
                            opt->value = std::string(val_part);
                        } else if (i + 1 < args.size() && !args[i + 1].starts_with("-")) {
                            opt->value = std::string(args[++i]);
                        } else {
                            res.success = false;
                            res.error_message = "Option --" + std::string(name_part) + " requires a value";
                            return res;
                        }
                    }
                }
                // Short option: -n or -n=value or -n value
                else if (arg.starts_with("-") && arg.size() > 1) {
                    char short_char = arg[1];
                    auto *opt = find_short_option_mut(short_char);
                    if (!opt) {
                        res.success = false;
                        res.error_message = std::string("Unknown option: -") + short_char;
                        return res;
                    }

                    opt->specified = true;
                    if (opt->type == OptionType::Flag) {
                        opt->value = "true";
                    } else {
                        if (arg.size() > 2) {
                            if (arg[2] == '=') {
                                opt->value = std::string(arg.substr(3));
                            } else {
                                opt->value = std::string(arg.substr(2));
                            }
                        } else if (i + 1 < args.size() && !args[i + 1].starts_with("-")) {
                            opt->value = std::string(args[++i]);
                        } else {
                            res.success = false;
                            res.error_message = std::string("Option -") + short_char + " requires a value";
                            return res;
                        }
                    }
                }
                // Positional argument
                else {
                    if (positional_idx < positionals_.size()) {
                        positionals_[positional_idx].specified = true;
                        positionals_[positional_idx].value = std::string(arg);
                        ++positional_idx;
                    } else {
                        extra_positionals_.emplace_back(arg);
                    }
                }
            }

            // Verify required options and positionals
            for (const auto &[name, opt]: options_) {
                if (opt.required && !opt.specified) {
                    res.success = false;
                    res.error_message = "Missing required option: --" + name;
                    return res;
                }
            }
            for (const auto &pos: positionals_) {
                if (pos.required && !pos.specified) {
                    res.success = false;
                    res.error_message = "Missing required positional argument: <" + pos.name + ">";
                    return res;
                }
            }

            return res;
        }

        /**
         * @brief Returns true if an option/flag was specified on the command line.
         */
        [[nodiscard]] bool has(const std::string &name) const {
            if (const auto *opt = find_option(name)) return opt->specified;
            for (const auto &pos: positionals_) {
                if (pos.name == name) return pos.specified;
            }
            return false;
        }

        /**
         * @brief Get option value as string.
         */
        [[nodiscard]] std::string get_string(const std::string &name) const {
            if (const auto *opt = find_option(name)) return opt->value;
            for (const auto &pos: positionals_) {
                if (pos.name == name) return pos.value;
            }
            return "";
        }

        /**
         * @brief Get option value as int with fallback.
         */
        [[nodiscard]] int get_int(const std::string &name, int default_val = 0) const {
            std::string val = get_string(name);
            if (val.empty()) return default_val;
            try {
                return std::stoi(val);
            } catch (...) {
                return default_val;
            }
        }

        /**
         * @brief Get option value as size_t with fallback.
         */
        [[nodiscard]] std::size_t get_size_t(const std::string &name, std::size_t default_val = 0) const {
            std::string val = get_string(name);
            if (val.empty()) return default_val;
            try {
                return static_cast<std::size_t>(std::stoull(val));
            } catch (...) {
                return default_val;
            }
        }

        /**
         * @brief Get option value as boolean.
         */
        [[nodiscard]] bool get_bool(const std::string &name) const {
            std::string val = get_string(name);
            return (val == "true" || val == "1" || val == "yes" || val == "ON");
        }

        /**
         * @brief Get option value as double with fallback.
         */
        [[nodiscard]] double get_double(const std::string &name, double default_val = 0.0) const {
            std::string val = get_string(name);
            if (val.empty()) return default_val;
            try {
                return std::stod(val);
            } catch (...) {
                return default_val;
            }
        }

        /**
         * @brief Access unhandled extra positional arguments.
         */
        [[nodiscard]] const std::vector<std::string> &extra_positionals() const {
            return extra_positionals_;
        }

        /**
         * @brief Generate usage help text.
         */
        [[nodiscard]] std::string help_message() const {
            std::ostringstream oss;
            oss << "Usage: " << (program_name_.empty() ? "app" : program_name_);
            if (!options_.empty()) oss << " [options]";
            for (const auto &pos: positionals_) {
                if (pos.required) oss << " <" << pos.name << ">";
                else oss << " [" << pos.name << "]";
            }
            oss << "\n";

            if (!description_.empty()) {
                oss << "\n" << description_ << "\n";
            }

            oss << "\nOptions:\n";
            for (const auto &name: option_order_) {
                const auto &opt = options_.at(name);
                oss << "  ";
                if (opt.short_name != '\0') {
                    oss << "-" << opt.short_name << ", ";
                } else {
                    oss << "    ";
                }
                oss << "--" << opt.name;
                if (opt.type == OptionType::Value) {
                    oss << " <val>";
                }

                size_t padding = (opt.name.size() + 10 < 28) ? 28 - (opt.name.size() + 10) : 2;
                oss << std::string(padding, ' ') << opt.description;

                if (!opt.default_value.empty() && opt.type == OptionType::Value) {
                    oss << " (default: " << opt.default_value << ")";
                }
                if (opt.required) {
                    oss << " [REQUIRED]";
                }
                oss << "\n";
            }

            if (!positionals_.empty()) {
                oss << "\nPositional Arguments:\n";
                for (const auto &pos: positionals_) {
                    oss << "  " << pos.name;
                    size_t padding = (pos.name.size() < 20) ? 20 - pos.name.size() : 2;
                    oss << std::string(padding, ' ') << pos.description;
                    if (pos.required) oss << " [REQUIRED]";
                    oss << "\n";
                }
            }

            return oss.str();
        }

        /**
         * @brief Print help message to stdout.
         */
        void print_help() const {
            std::cout << help_message();
        }

    private:
        void register_option(Option opt) {
            std::string name = opt.name;
            if (opt.short_name != '\0') {
                short_index_[opt.short_name] = name;
            }
            options_[name] = std::move(opt);
            option_order_.push_back(name);
        }

        [[nodiscard]] const Option *find_option(const std::string &name) const {
            auto it = options_.find(name);
            return (it != options_.end()) ? &it->second : nullptr;
        }

        [[nodiscard]] Option *find_option_mut(const std::string &name) {
            auto it = options_.find(name);
            return (it != options_.end()) ? &it->second : nullptr;
        }

        [[nodiscard]] Option *find_short_option_mut(char c) {
            auto it = short_index_.find(c);
            if (it != short_index_.end()) {
                return find_option_mut(it->second);
            }
            return nullptr;
        }

        std::string program_name_;
        std::string description_;
        std::unordered_map<std::string, Option> options_;
        std::unordered_map<char, std::string> short_index_;
        std::vector<std::string> option_order_;
        std::vector<Option> positionals_;
        std::vector<std::string> extra_positionals_;
    };
} // namespace wavex::cli
