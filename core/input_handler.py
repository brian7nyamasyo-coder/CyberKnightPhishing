
def get_required_input(prompt):
    """Keep asking until the user enters non-empty input."""

    while True:
        value = input(prompt).strip()

        if value:
            return value

        print("Input cannot be empty. Please try again.")


def get_multiline_input(title):
    """Collect multiline input until END is entered."""

    print(f"\n{title}")
    print("Type END on a separate line when finished.\n")

    lines = []

    while True:
        line = input()

        if line.strip().upper() == "END":
            break

        lines.append(line)

    return "\n".join(lines)
