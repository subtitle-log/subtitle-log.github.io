---
title: "Building a C Vulnerability Scanner with AST Walking"
summary: "Why regex grep is not enough for C static analysis, and how pycparser's AST lets you catch format string bugs, unchecked allocs, and command injection by walking the actual parse tree."
date: 2026-11-26
tags: ["AST", "Static Analysis", "pycparser", "C"]
draft: false
featured: true
category: Tooling
---

Most static analysis tutorials for C start with regex. Run grep for `gets` or `strcpy`, flag the line, done. It works for the obvious cases, but it breaks down fast. A regex cannot tell whether the first argument to `printf` is a string literal or a user-controlled variable. It cannot track whether a `malloc` return value was checked before use. It has no concept of function scope or argument position.

I wanted to build something that actually understands the code structure. Not a production-grade tool, but one that demonstrates why tree-based analysis matters and catches real patterns that grep misses.

The result is [c-ast-scanner](https://github.com/charlie-morningstar/c-ast-scanner), a Python tool that parses C source into a full Abstract Syntax Tree with pycparser and walks the tree to detect vulnerability patterns.

## Why AST over regex

Consider this line:

```c
fprintf(fp, user_input);
```

A regex looking for `fprintf` might flag it as a dangerous function. But the actual problem is not `fprintf` itself. The problem is that the second argument (the format string) is not a string literal. If `user_input` contains `%x%x%x`, the attacker reads the stack.

To detect this properly, you need to know:
1. That `fprintf` takes the format string as argument index 1 (not 0, like `printf`)
2. Whether that argument is a `Constant` node (string literal) or something else in the AST

A regex sees text. An AST sees structure. That distinction is what makes format string detection actually work.

## How pycparser builds the tree

pycparser is a pure-Python C parser. It runs the C source through the gcc preprocessor (`gcc -E`) to resolve includes and macros, then parses the result into a tree of `c_ast` node objects. Each node type maps to a C construct: `FuncCall`, `Decl`, `Assignment`, `If`, `BinaryOp`, and so on.

There is one practical hurdle. pycparser cannot parse real system headers like `stdio.h` because they contain gcc-specific extensions and builtins. The standard workaround is fake libc headers: minimal stubs that define just enough (typedefs, function declarations) for the parser to accept `#include <stdio.h>` without choking.

The scanner bundles these fake headers and passes them to gcc:

```python
ast = parse_file(filepath, use_cpp=True,
                 cpp_path="gcc",
                 cpp_args=["-E", "-nostdinc",
                           "-D__attribute__(x)=",
                           f"-I{fake_libc_dir}"])
```

`-nostdinc` tells gcc to ignore real system headers. `-I` points to the fakes. `-D__attribute__(x)=` neutralizes `__attribute__` annotations that pycparser does not understand.

When gcc is not available (some CI environments, Windows without MinGW), the scanner falls back to stripping comments with regex and parsing directly with `CParser()`. It loses macro expansion but still builds a usable tree.

## Walking the tree with NodeVisitor

pycparser provides `c_ast.NodeVisitor`, a base class with a visitor pattern. You subclass it and define `visit_<NodeType>` methods. The visitor dispatches each node to the matching method as it walks the tree.

The scanner's `VulnVisitor` overrides five node types: `FuncCall`, `Decl`, `Assignment`, `If`, and `FuncDef`. Each one maps to a detection rule.

### Rule 1: Dangerous function calls

The simplest rule. A dictionary maps function names to severity, CWE number, and suggested fix:

```python
DANGEROUS_FUNCS = {
    "gets":   ("HIGH",   "CWE-120", "fgets()"),
    "strcpy": ("MEDIUM", "CWE-120", "strncpy() or strlcpy()"),
    "system": ("HIGH",   "CWE-78",  "execve() with validated input"),
    "popen":  ("HIGH",   "CWE-78",  "pipe()/fork()/exec()"),
    # ...
}
```

When `visit_FuncCall` fires and the callee name is in the dictionary, the scanner emits a finding. This is essentially what grep does, but through the AST we know it is an actual function call, not a comment or a string containing the word.

### Rule 2: Format string detection

This is where AST walking pays off. The `PRINTF_FAMILY` dictionary maps each printf-family function to the index of its format argument:

```python
PRINTF_FAMILY = {
    "printf": 0,    # printf(fmt, ...)
    "fprintf": 1,   # fprintf(fp, fmt, ...)
    "snprintf": 2,  # snprintf(buf, size, fmt, ...)
}
```

The check looks at the actual argument node at that index. If it is not a `c_ast.Constant` (a literal string), the scanner flags it as CWE-134:

```python
args = node.args.exprs
fmt_idx = PRINTF_FAMILY[name]
if not isinstance(args[fmt_idx], c_ast.Constant):
    # format string is not a literal -> CWE-134
```

No regex can do this correctly across all printf variants without false positives on comments and strings, or false negatives on `fprintf` where the format arg is at index 1 instead of 0.

### Rule 3: Unchecked memory allocation

This rule requires tracking state across multiple AST nodes, which is impossible with line-by-line analysis.

The idea: when `malloc`, `calloc`, or `realloc` appears on the right side of a declaration or assignment, record the variable name. If the function ends without an `if` condition that references that variable, the allocation was never NULL-checked.

The implementation uses three visitor callbacks:

- `visit_Decl` and `visit_Assignment`: when the right-hand side is an alloc call, store `{var_name: (line, col, func)}` in a pending dictionary
- `visit_If`: walk the condition subtree. Any `ID` node matching a pending variable name resolves the check (removes it from pending)
- `visit_FuncDef`: at function entry, save and clear the pending dictionary. At function exit, anything still pending was never checked. Emit CWE-252 findings for each one, then restore the saved state.

One subtlety: standalone alloc calls (not assigned to any variable) are caught differently. The visitor tracks which `FuncCall` nodes appear inside `Decl` or `Assignment` by storing `id(node)` in a set. Any alloc call not in that set means the return value was thrown away entirely.

## What it does not catch

Being honest about limitations matters more than inflating the feature list.

- No cross-function analysis. If function A calls `malloc` and returns the pointer to function B, the scanner does not track that chain.
- No taint propagation. The format string check is literal vs non-literal. If a local variable holds a copy of a user-controlled string and gets passed to `printf`, the scanner sees a local variable (non-literal) and flags it. But it cannot distinguish between `char *fmt = "%s"` (safe, just indirect) and `char *fmt = user_input` (actually dangerous).
- NULL check detection is limited to direct `if` conditions. Assertions, wrapper macros, and early-return patterns through helper functions are not recognized.
- C only. No C++, no binary analysis.

These are inherent limits of local AST walking without dataflow analysis. A real production tool like Coverity or the Clang Static Analyzer builds control flow graphs and tracks value ranges across paths. This scanner stays at the AST node level, which keeps the code small and the analysis transparent.

## Running it

```bash
$ python3 scanner.py samples/vuln_example.c

c-ast-scanner
scanning 1 file(s)...

--- samples/vuln_example.c (15 issue(s)) ---
  [HIGH] line 16:5    dangerous-func (CWE-120): gets() -> use fgets()
  [HIGH] line 32:5    dangerous-func (CWE-78): system() -> use execve()
  [HIGH] line 46:5    format-string (CWE-134): printf() format arg is not a literal
  [MEDIUM] line 57:16  unchecked-alloc (CWE-252): malloc() result not NULL-checked
  ...

total: 15 issue(s)  [HIGH:6 MEDIUM:9 LOW:0]
```

The `--min-severity HIGH` flag filters output for triage. `--json` outputs structured data for integration with other tools.

## What I learned

Parsing C is harder than it looks. Real-world C headers are full of compiler extensions that no pure parser handles cleanly. The fake libc header approach is a well-known workaround in the pycparser ecosystem, but understanding why it is necessary (and what it costs in terms of lost type information) was part of the exercise.

The NodeVisitor pattern is a natural fit for rule-based scanning. Each rule maps to one or two node types, and the visitor dispatches automatically. Adding a new rule means adding a dictionary entry and optionally a new visit method.

The biggest gap between this and a production static analyzer is dataflow. Knowing that a variable holds a pointer from `malloc` is local. Knowing where that pointer came from across function boundaries requires a call graph and path-sensitive analysis. That is where tools like Clang's `scan-build` start, and where this scanner deliberately stops.

Source code: [charlie-morningstar/c-ast-scanner](https://github.com/charlie-morningstar/c-ast-scanner)
