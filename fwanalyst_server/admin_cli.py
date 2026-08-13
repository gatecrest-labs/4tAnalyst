"""Admin CLI tool for user management (create/delete/list/reset-password).

Entry point: `python -m fwanalyst_server.admin` or `fwanalyst-admin` (installed script).

Security: passwords are NEVER accepted as CLI arguments. Interactive prompts use
getpass.getpass() to read from the terminal without echoing. Tests patch
getpass.getpass() to supply passwords.
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import sys
from pathlib import Path

from fwanalyst_server.admin_auth import hash_password, load_users, save_users

_DEFAULT_USERS_PATH = str(Path(__file__).parent.parent / "data" / "users.json")


def create_user(username: str, role: str, password: str, users_path: str) -> None:
    """Create a new user with the given username, role, and password.

    Args:
        username: The username (must be unique).
        role: The user role (e.g., 'admin', 'viewer').
        password: The plaintext password (will be hashed).
        users_path: Path to users.json file.

    Raises:
        ValueError: If the user already exists.
    """
    users = load_users(users_path)
    if username in users:
        raise ValueError(f"User '{username}' already exists.")
    users[username] = {
        "password_hash": hash_password(password),
        "role": role,
        "created_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
    }
    save_users(users_path, users)


def delete_user(username: str, users_path: str) -> None:
    """Delete an existing user.

    Args:
        username: The username to delete.
        users_path: Path to users.json file.

    Raises:
        KeyError: If the user does not exist.
    """
    users = load_users(users_path)
    if username not in users:
        raise KeyError(f"User '{username}' not found.")
    del users[username]
    save_users(users_path, users)


def list_users(users_path: str) -> list[dict]:
    """List all users.

    Args:
        users_path: Path to users.json file.

    Returns:
        A list of dicts with keys: username, role, password_hash, created_at.
    """
    users = load_users(users_path)
    return [{"username": k, **v} for k, v in users.items()]


def reset_password(username: str, new_password: str, users_path: str) -> None:
    """Reset a user's password.

    Args:
        username: The username whose password to reset.
        new_password: The new plaintext password (will be hashed).
        users_path: Path to users.json file.

    Raises:
        KeyError: If the user does not exist.
    """
    users = load_users(users_path)
    if username not in users:
        raise KeyError(f"User '{username}' not found.")
    users[username]["password_hash"] = hash_password(new_password)
    save_users(users_path, users)


def main() -> None:
    """CLI entry point for user management.

    Usage:
        python -m fwanalyst_server.admin <command> [args]

    Commands:
        create-user <username> --role {admin,viewer}
            Create a new user (prompts for password interactively).

        delete-user <username>
            Delete an existing user.

        list-users
            List all users (username, role, created_at).

        reset-password <username>
            Reset a user's password (prompts interactively).
    """
    parser = argparse.ArgumentParser(
        prog="python -m fwanalyst_server.admin",
        description="Manage 4tAnalyst admin users.",
    )
    sub = parser.add_subparsers(dest="cmd", help="Available commands")

    # create-user
    p = sub.add_parser("create-user", help="Create a new user")
    p.add_argument("username", help="Username")
    p.add_argument("--role", choices=["admin", "viewer"], required=True, help="User role")

    # delete-user
    p = sub.add_parser("delete-user", help="Delete a user")
    p.add_argument("username", help="Username to delete")

    # list-users
    sub.add_parser("list-users", help="List all users")

    # reset-password
    p = sub.add_parser("reset-password", help="Reset a user's password")
    p.add_argument("username", help="Username")

    args = parser.parse_args()
    users_path = _DEFAULT_USERS_PATH

    if args.cmd == "create-user":
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Confirm: "):
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
        try:
            create_user(args.username, args.role, pw, users_path)
            print(f"Created '{args.username}' ({args.role}).")
        except ValueError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    elif args.cmd == "delete-user":
        try:
            delete_user(args.username, users_path)
            print(f"Deleted '{args.username}'.")
        except KeyError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)

    elif args.cmd == "list-users":
        for u in list_users(users_path):
            print(f"{u['username']:<20} {u['role']:<10} {u.get('created_at', '')}")

    elif args.cmd == "reset-password":
        pw = getpass.getpass("New password: ")
        if pw != getpass.getpass("Confirm: "):
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
        try:
            reset_password(args.username, pw, users_path)
            print(f"Password reset for '{args.username}'.")
        except KeyError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
