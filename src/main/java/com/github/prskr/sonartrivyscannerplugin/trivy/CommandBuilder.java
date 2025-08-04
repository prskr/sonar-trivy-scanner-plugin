package com.github.prskr.sonartrivyscannerplugin.trivy;

import java.util.*;

public record CommandBuilder(String name, Collection<CommandArgument> arguments) {

    public static CommandBuilder builder(String name) {
        return new CommandBuilder(name, Collections.emptyList());
    }

    public CommandBuilder withArguments(CommandArgument... arguments) {
        return withArguments(Arrays.asList(arguments));
    }

    public CommandBuilder withArguments(Collection<CommandArgument> flags) {
        var allArgs = new LinkedList<>(this.arguments);
        allArgs.addAll(flags);

        return new CommandBuilder(name, Collections.unmodifiableList(allArgs));
    }

    public CommandBuilder withPositionalArgument(String value) {
        return withArguments(new PositionalArgument(value));
    }

    public CommandBuilder withFlag(String name, String value) {
        return withArguments(new Flag(name, value));
    }

    public CommandBuilder withFlag(String name) {
        return withArguments(new NoValueFlag(name));
    }

    public String[] build() {
        String[] command = new String[arguments.size() + 1];
        command[0] = name;

        var i = 1;
        for(var argument : arguments) {
            if (argument.isEmpty()) {
                continue;
            }
            command[i++] = argument.format();
        }

        return command;
    }

    public interface CommandArgument {
        String format();
        boolean isEmpty();
    }

    public record PositionalArgument(String value) implements CommandArgument {
        @Override
        public String format() {
            return value;
        }

        @Override
        public boolean isEmpty() {
            return value.isEmpty();
        }
    }

    public record NoValueFlag(String name) implements CommandArgument {
        @Override
        public String format() {
            return String.format("--%s", name);
        }

        @Override
        public boolean isEmpty() {
            return name.isEmpty();
        }
    }

    public record Flag(String name, String value) implements CommandArgument {
        public Flag {
            name = name.replaceFirst("^--", "");
        }

        @Override
        public String format() {
            return String.format("--%s=%s", name, value);
        }

        public boolean isEmpty() {
            return name.isEmpty() || value.isEmpty();
        }
    }
}
