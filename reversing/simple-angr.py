import angr
import claripy

BINARY = "CrackThePassword"
INPUT_LENGTH = 33

proj = angr.Project(
    BINARY,
    main_opts={'base_addr': 0x0},
    load_options={'auto_load_libs': False}
)

flag = claripy.BVS("flag", 8 * INPUT_LENGTH)

state = proj.factory.entry_state(stdin=flag)

# Silence the warnings
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

sm = proj.factory.simulation_manager(state)

FIND_ADDR = 0x1652   # Any address we want
AVOID_ADDR = 0x1663  # Any address we dont want

sm.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

print("[*] Flag found: " + sm.found[0].posix.dumps(0).decode("utf-8"))
