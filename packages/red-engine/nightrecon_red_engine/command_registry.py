"""Trusted executable registry for the governed command runner.

Only explicitly registered immutable definitions may execute. This is a local
single-coordinator adapter; it does not grant network or elevation privileges.
"""
from __future__ import annotations
from dataclasses import dataclass
from .governed_command_runner import FixedCommand, CommandOutcome, execute_fixed_command

class CommandRegistry:
    def __init__(self, commands: tuple[FixedCommand,...]):
        names=[item.name for item in commands]
        if len(names)!=len(set(names)):
            raise ValueError("Duplicate command definition")
        self._commands={item.name:item for item in commands}
    def get(self, name: str)->FixedCommand:
        if name not in self._commands:
            raise PermissionError("Command not registered")
        return self._commands[name]
    def names(self)->tuple[str,...]:
        return tuple(sorted(self._commands))

def execute_registered(*, registry:CommandRegistry, name:str, **kwargs)->CommandOutcome:
    """Never accept an executable path or argument vector from the request."""
    return execute_fixed_command(command=registry.get(name),**kwargs)
