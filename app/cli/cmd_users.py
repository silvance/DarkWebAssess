"""User management commands."""
import sys

from app.cli._helpers import prompt_password
from app.database import db_cursor


def register(sub):
    pu = sub.add_parser("user", help="Manage dashboard users (auth).")
    us = pu.add_subparsers(dest="user_command", required=True)

    uc = us.add_parser("create", help="Create a new user.")
    uc.add_argument("username")
    uc.add_argument("--role", default="analyst", choices=["viewer", "analyst", "admin"])
    uc.add_argument("--full-name")
    uc.add_argument("--password", help="Set the password (otherwise prompted).")
    uc.set_defaults(func=cmd_user_create)

    us.add_parser("list", help="List users.").set_defaults(func=cmd_user_list)

    usp = us.add_parser("set-password", help="Reset a user's password.")
    usp.add_argument("username")
    usp.add_argument("--password", help="Set the password (otherwise prompted).")
    usp.set_defaults(func=cmd_user_set_password)

    usr = us.add_parser("set-role", help="Change a user's role.")
    usr.add_argument("username")
    usr.add_argument("role", choices=["viewer", "analyst", "admin"])
    usr.set_defaults(func=cmd_user_set_role)

    use = us.add_parser("disable", help="Disable a user.")
    use.add_argument("username")
    use.set_defaults(func=cmd_user_disable)

    uen = us.add_parser("enable", help="Re-enable a user.")
    uen.add_argument("username")
    uen.set_defaults(func=cmd_user_enable)

    udel = us.add_parser("delete", help="Delete a user.")
    udel.add_argument("username")
    udel.set_defaults(func=cmd_user_delete)


def cmd_user_create(args):
    from app.auth.passwords import WeakPasswordError
    from app.auth.users import create_user

    password = prompt_password(args.password)
    with db_cursor() as conn:
        try:
            uid = create_user(
                conn, args.username, password,
                role=args.role, full_name=args.full_name, actor="cli",
            )
        except WeakPasswordError as exc:
            print(f"ERROR: {exc}")
            sys.exit(1)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            sys.exit(1)
    print(f"Created user #{uid} ({args.username}, role={args.role})")


def cmd_user_list(_args):
    from app.auth.users import list_users

    with db_cursor() as conn:
        users = list_users(conn)
    if not users:
        print("No users.")
        return
    for u in users:
        flag = "" if u["enabled"] else " (disabled)"
        last = u["last_login_at"] or "—"
        print(f"  {u['username']:<20} {u['role']:<8} last_login={last}{flag}")


def cmd_user_set_password(args):
    from app.auth.passwords import WeakPasswordError
    from app.auth.users import set_password

    password = prompt_password(args.password)
    with db_cursor() as conn:
        try:
            ok = set_password(conn, args.username, password, actor="cli")
        except WeakPasswordError as exc:
            print(f"ERROR: {exc}")
            sys.exit(1)
        if not ok:
            print(f"User {args.username!r} not found.")
            sys.exit(1)
    print(f"Password updated for {args.username}.")


def cmd_user_set_role(args):
    from app.auth.users import set_role

    with db_cursor() as conn:
        if not set_role(conn, args.username, args.role, actor="cli"):
            print(f"User {args.username!r} not found.")
            sys.exit(1)
    print(f"Role for {args.username} → {args.role}")


def cmd_user_disable(args):
    from app.auth.users import set_enabled

    with db_cursor() as conn:
        if not set_enabled(conn, args.username, False, actor="cli"):
            print(f"User {args.username!r} not found.")
            sys.exit(1)
    print(f"Disabled {args.username}.")


def cmd_user_enable(args):
    from app.auth.users import set_enabled

    with db_cursor() as conn:
        if not set_enabled(conn, args.username, True, actor="cli"):
            print(f"User {args.username!r} not found.")
            sys.exit(1)
    print(f"Enabled {args.username}.")


def cmd_user_delete(args):
    from app.auth.users import delete_user

    with db_cursor() as conn:
        if not delete_user(conn, args.username, actor="cli"):
            print(f"User {args.username!r} not found.")
            sys.exit(1)
    print(f"Deleted {args.username}.")
