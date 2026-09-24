def add_one(value):
    adjusted = value + 1
    return adjusted


def run(dbg):
    first = 1
    second = add_one(first)
    third = add_one(second)
    print(f"script-debugger-value={third}")
