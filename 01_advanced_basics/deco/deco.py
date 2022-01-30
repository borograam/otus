#!/usr/bin/env python
# -*- coding: utf-8 -*-
import itertools
from functools import update_wrapper
from itertools import chain
from copy import deepcopy


def disable(func):
    '''
    Disable a decorator by re-assigning the decorator's name
    to this function. For example, to turn off memoization:

    >>> memo = disable

    '''
    return func


def decorator(dec_func):
    '''
    Decorate a decorator so that it inherits the docstrings
    and stuff from the function it's decorating.
    '''
    class Decorator:
        _need_to_init = {}
        # _dec_func = dec_func

        def __init__(self, func):
            self._func = func
            for k, v in self._need_to_init.items():
                setattr(self, k, deepcopy(v))
            update_wrapper(self, func, updated=[])

        def __call__(self, *args, **kwargs):
            return dec_func(self._func, args, kwargs, mem=self)

        def __getattribute__(self, item):
            try:
                return super().__getattribute__(item)
            except AttributeError:
                return getattr(self._func, item)

        @classmethod
        def init(cls, **kwargs):
            cls._need_to_init.update(kwargs)

    return Decorator


@decorator
def countcalls(func, args, kwargs, mem):
    '''Decorator that counts calls made to the function decorated.'''
    mem.calls += 1
    return func(*args, **kwargs)

countcalls.init(calls=0)


@decorator
def memo(func, args, kwargs, mem):
    '''
    Memoize a function so that it caches all return values for
    faster future lookups.
    '''
    key = tuple(chain(args, kwargs.items()))
    if key in mem.cache:
        return mem.cache[key]
    result = func(*args, **kwargs)
    mem.cache[key] = result
    return result

memo.init(cache={})


@decorator
def n_ary(func, args, kwargs, mem):
    '''
    Given binary function f(x, y), return an n_ary function such
    that f(x, y, z) = f(x, f(y,z)), etc. Also allow f(x) = x.
    '''
    if not args:
        raise TypeError('takes positional arguments')
    acc_arg = args[-1]
    for next_arg in args[-2::-1]:
        acc_arg = func(next_arg, acc_arg)
    return acc_arg


def trace(sep):
    '''Trace calls made to function decorated.

    @trace("____")
    def fib(n):
        ....

    >>> fib(3)
     --> fib(3)
    ____ --> fib(2)
    ________ --> fib(1)
    ________ <-- fib(1) == 1
    ________ --> fib(0)
    ________ <-- fib(0) == 1
    ____ <-- fib(2) == 2
    ____ --> fib(1)
    ____ <-- fib(1) == 1
     <-- fib(3) == 3

    '''
    @decorator
    def dec(func, args, kwargs, mem):
        func_args = ", ".join(itertools.chain(
            (str(a) for a in args),
            (f'{k}={v}' for k, v in kwargs.items())
        ))
        func_call = f'{func.__name__}({func_args})'
        print(f'{sep * mem.nested} --> {func_call}')

        mem.nested += 1
        result = func(*args, **kwargs)
        mem.nested -= 1

        print(f'{sep * mem.nested} <-- {func_call} == {result}')
        return result
    dec.init(nested=0)
    return dec



@memo
@countcalls
@n_ary
def foo(a, b):
    return a + b


@countcalls
@memo
@n_ary
def bar(a, b):
    return a * b


@countcalls
@trace("    ")
@memo
def fib(n):
    """Some doc"""
    return 1 if n <= 1 else fib(n-1) + fib(n-2)


def main():
    print(foo(4, 3))
    print(foo(4, 3, 2))
    print(foo(4, 3))
    print("foo was called", foo.calls, "times")

    print(bar(4, 3))
    print(bar(4, 3, 2))
    print(bar(4, 3, 2, 1))
    print("bar was called", bar.calls, "times")

    print(fib.__doc__)
    fib(10)
    print(fib.calls, 'calls made')
    # 19 - т.к. счётчик стоит до мемоизации, так что вытягивание значения из кеша тоже считается.
    # Я бы переставил memo и countcalls местами, тогда будет 11 (что соответствует идеологически и трейсу)


if __name__ == '__main__':
    main()
