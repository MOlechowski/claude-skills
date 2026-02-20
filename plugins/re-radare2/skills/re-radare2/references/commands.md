# radare2 Command Reference

Complete command reference organized by category.

## Command Structure

Commands follow patterns:
- Single letter = category (a=analysis, p=print, w=write, d=debug)
- Second letter = subcategory
- `?` after command = help
- `j` suffix = JSON output

## Analysis Commands (a)

| Command | Description |
|---------|-------------|
| `aa` | Analyze basic blocks |
| `aaa` | Analyze all (autoname, calls, refs) |
| `aaaa` | Even more analysis |
| `aab` | Analyze basic blocks in range |
| `aac` | Analyze function calls |
| `aae` | Analyze emulation |
| `aaf` | Analyze functions |
| `afl` | List functions |
| `afll` | List functions (verbose) |
| `aflj` | List functions (JSON) |
| `afn name` | Rename function |
| `afvn name addr` | Rename variable |
| `afi` | Show function info |
| `afb` | List basic blocks |
| `axt addr` | Find xrefs to address |
| `axf addr` | Find xrefs from address |
| `ax` | List all xrefs |
| `agc` | Call graph (current function) |
| `agC` | Global call graph |
| `agf` | Flow graph (current function) |

## Print Commands (p)

| Command | Description |
|---------|-------------|
| `pd N` | Disassemble N instructions |
| `pD N` | Disassemble N bytes |
| `pdf` | Disassemble function |
| `pdc` | Pseudo-C decompilation |
| `pdg` | Ghidra decompilation |
| `pds` | Function summary |
| `px N` | Hexdump N bytes |
| `pxw N` | Hexdump as words |
| `pxq N` | Hexdump as qwords |
| `pxr N` | Hexdump with refs |
| `ps` | Print string |
| `psz` | Print zero-terminated string |
| `psp` | Print pascal string |
| `pf fmt` | Print formatted |
| `pfo` | Print struct formats |

## Seek Commands (s)

| Command | Description |
|---------|-------------|
| `s addr` | Seek to address |
| `s name` | Seek to flag/symbol |
| `s+ N` | Seek forward N bytes |
| `s- N` | Seek backward N bytes |
| `s--` | Undo seek |
| `s++` | Redo seek |
| `s*` | Show seek history |

## Write Commands (w)

| Command | Description |
|---------|-------------|
| `w string` | Write string |
| `wx hex` | Write hex bytes |
| `wa asm` | Write assembly |
| `wao op` | Write operation (nop, jmp, etc.) |
| `wc` | List write cache |
| `wci` | Commit write cache |
| `wcr` | Reset write cache |

### wao Operations

| Operation | Description |
|-----------|-------------|
| `wao nop` | Replace instruction with NOPs |
| `wao jmp` | Convert to unconditional jump |
| `wao cjmp` | Convert to conditional jump |
| `wao call` | Convert to call |
| `wao trap` | Convert to trap (int3) |
| `wao ret` | Convert to return |

## Debug Commands (d)

| Command | Description |
|---------|-------------|
| `db addr` | Set breakpoint |
| `db -addr` | Remove breakpoint |
| `dbl` | List breakpoints |
| `dbc addr cmd` | Breakpoint with command |
| `dbe addr` | Enable breakpoint |
| `dbd addr` | Disable breakpoint |
| `dc` | Continue execution |
| `dcc` | Continue until call |
| `dcr` | Continue until return |
| `dcu addr` | Continue until address |
| `ds` | Step into |
| `dso` | Step over |
| `dsf` | Step until end of frame |
| `dr` | Show registers |
| `dr reg` | Show specific register |
| `dr reg=val` | Set register value |
| `drr` | Show register references |
| `dm` | Memory maps |
| `dmm` | List modules |
| `dmp` | Memory permissions |

## Information Commands (i)

| Command | Description |
|---------|-------------|
| `i` | File info |
| `ia` | All info |
| `ib` | Binary info |
| `ic` | Classes |
| `iC` | Signature |
| `ie` | Entrypoints |
| `iE` | Exports |
| `ih` | Headers |
| `ii` | Imports |
| `iS` | Sections |
| `is` | Symbols |
| `iz` | Strings (data section) |
| `izz` | All strings |
| `il` | Libraries |
| `ir` | Relocations |

## Search Commands (/)

| Command | Description |
|---------|-------------|
| `/ string` | Search string |
| `/x hex` | Search hex pattern |
| `/a asm` | Search assembly |
| `/r addr` | Search refs to address |
| `/c` | Search crypto constants |
| `/m` | Search magic bytes |
| `/v value` | Search numeric value |
| `/w string` | Search wide string |
| `/e regexp` | Search regex |

## Flag Commands (f)

| Command | Description |
|---------|-------------|
| `f name` | Add flag at current seek |
| `f name @ addr` | Add flag at address |
| `f-name` | Remove flag |
| `fl` | List flags |
| `fs` | List flagspaces |
| `fs name` | Select flagspace |

## Comment Commands (C)

| Command | Description |
|---------|-------------|
| `CC text` | Add comment |
| `CC-` | Remove comment |
| `CCf` | Function comment |
| `CCu` | Unique comment |

## Type Commands (t)

| Command | Description |
|---------|-------------|
| `t` | List types |
| `td struct` | Define struct |
| `te` | List enums |
| `ts` | List structs |
| `tu` | List unions |
| `to file` | Load types from file |

## Project Commands (P)

| Command | Description |
|---------|-------------|
| `Ps name` | Save project |
| `Po name` | Open project |
| `Pd` | Delete project |
| `Pl` | List projects |

## Visual Mode Commands

### Global (V)

| Key | Action |
|-----|--------|
| `j/k` | Move down/up |
| `J/K` | Page down/up |
| `g/G` | Top/bottom |
| `h/l` | Byte left/right |
| `:` | Command prompt |
| `p/P` | Rotate modes |
| `q` | Quit |
| `c` | Cursor mode |
| `i` | Insert mode |
| `A` | Assemble |
| `d` | Define |
| `n` | Seek to next function |
| `N` | Seek to previous function |
| `u` | Undo seek |
| `U` | Redo seek |

### Graph Mode (VV)

| Key | Action |
|-----|--------|
| `hjkl` | Navigate |
| `space` | Toggle node |
| `tab` | Next block |
| `TAB` | Previous block |
| `t/f` | True/false branch |
| `p` | Rotate graph modes |
| `+/-` | Zoom |
| `0` | Reset zoom |
| `g` | Seek node |
| `u` | Undo seek |
| `/` | Search |

## Environment Variables (e)

| Variable | Description |
|----------|-------------|
| `e asm.arch` | Architecture |
| `e asm.bits` | Bits (32/64) |
| `e asm.syntax` | Syntax (intel/att) |
| `e scr.color` | Color mode (0-3) |
| `e dbg.follow` | Follow execution |
| `e io.cache` | Write cache |
| `e anal.depth` | Analysis depth |
| `e bin.strings` | Detect strings |

## Special Addresses

| Symbol | Description |
|--------|-------------|
| `@` | At address |
| `@@` | Iterate |
| `@@@` | Iterate all |
| `$` | Current seek |
| `$$` | Current address |
| `$s` | File size |
| `$b` | Block size |
| `$e` | Entry point |
