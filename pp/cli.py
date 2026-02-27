from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .attest import create_attestation, verify_attestation
from .config import load_config
from .session import SessionController


def _cmd_run(args: argparse.Namespace) -> int:
    controller = SessionController(Path.cwd())
    summary = controller.run(
        command=args.command,
        policy_path=args.policy,
        provider_name=args.provider,
        keep_sandbox=args.keep_sandbox,
        attest=args.attest,
        attestation_mode=args.attestation_mode,
        attestation_key_env=args.attestation_key_env,
    )

    print(f"success={summary.success}")
    print(f"attempts_used={summary.attempts_used}")
    print(f"final_exit_code={summary.final_result.exit_code}")
    print(f"final_patch={summary.final_patch_path}")
    print(f"proof_bundle={summary.proof_bundle_dir}")
    if summary.extra.get("attestation_path"):
        print(f"attestation={summary.extra['attestation_path']}")

    return 0 if summary.success else 2


def _cmd_replay(args: argparse.Namespace) -> int:
    controller = SessionController(Path.cwd())
    bundle = Path(args.bundle).resolve()
    cwd = Path(args.cwd).resolve() if args.cwd else None
    result = controller.replay(
        bundle,
        cwd_override=cwd,
        verify_bundle_attestation=args.verify_attestation,
    )

    print(f"success={result['success']}")
    print(f"exit_code={result['exit_code']}")
    print(f"duration_sec={result['duration_sec']:.3f}")
    print("--- stdout ---")
    print(result["stdout"])
    print("--- stderr ---")
    print(result["stderr"])
    if args.verify_attestation:
        print("--- attestation ---")
        print(result.get("attestation"))

    return 0 if result["success"] else 2


def _cmd_doctor(args: argparse.Namespace) -> int:
    command = args.command or "true"
    config, resolved = load_config(args.policy, command, Path.cwd())
    print("Patch & Prove doctor")
    print(f"policy_path={resolved if resolved else '(default)'}")
    print(f"allowed_commands={config.policy.allowed_commands}")
    print(f"write_allowlist={config.policy.write_allowlist}")
    print(f"deny_write={config.policy.deny_write}")
    print(f"max_attempts={config.policy.limits.max_attempts}")
    print(f"sandbox_backend={config.policy.sandbox.backend}")
    print(f"container_runtime={config.policy.sandbox.container_runtime}")
    print(f"container_image={config.policy.sandbox.container_image}")
    print(f"attestation_enabled={config.policy.attestation.enabled}")
    print(f"attestation_mode={config.policy.attestation.mode}")
    return 0


def _cmd_attest(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle).resolve()
    path = create_attestation(bundle, mode=args.mode, key_env=args.key_env)
    print(f"attestation={path}")
    return 0


def _cmd_verify_attestation(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle).resolve()
    result = verify_attestation(bundle)
    print(result)
    return 0 if result.get("ok") else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pp", description="Patch & Prove CLI")
    sub = parser.add_subparsers(dest="subcmd", required=True)

    run_p = sub.add_parser("run", help="Run patch-and-prove on a failing command")
    run_p.add_argument("command", help="Proof target command, e.g. 'pytest -q'")
    run_p.add_argument("--policy", help="Path to pp.yaml/pp.json")
    run_p.add_argument("--provider", help="Provider name: stub|openai")
    run_p.add_argument("--keep-sandbox", action="store_true", help="Do not delete sandbox on exit")
    run_p.add_argument("--attest", action="store_true", help="Emit attestation.json for proof bundle")
    run_p.add_argument(
        "--attestation-mode",
        choices=["none", "hmac-sha256"],
        help="Attestation signing mode override",
    )
    run_p.add_argument(
        "--attestation-key-env",
        help="Environment variable name containing key for hmac-sha256 attestation",
    )
    run_p.set_defaults(func=_cmd_run)

    replay_p = sub.add_parser("replay", help="Replay proof target from proof bundle")
    replay_p.add_argument("bundle", help="Path to proof_bundle directory")
    replay_p.add_argument("--cwd", help="Override replay working directory")
    replay_p.add_argument(
        "--verify-attestation",
        action="store_true",
        help="Verify bundle attestation while replaying",
    )
    replay_p.set_defaults(func=_cmd_replay)

    doctor_p = sub.add_parser("doctor", help="Validate policy and runtime settings")
    doctor_p.add_argument("--policy", help="Path to policy file")
    doctor_p.add_argument("--command", help="Command to check against allowed_commands")
    doctor_p.set_defaults(func=_cmd_doctor)

    attest_p = sub.add_parser("attest", help="Create or overwrite proof-bundle attestation")
    attest_p.add_argument("bundle", help="Path to proof_bundle directory")
    attest_p.add_argument("--mode", choices=["none", "hmac-sha256"], default="none")
    attest_p.add_argument("--key-env", default="PP_ATTEST_HMAC_KEY")
    attest_p.set_defaults(func=_cmd_attest)

    verify_p = sub.add_parser("verify-attestation", help="Verify proof-bundle attestation")
    verify_p.add_argument("bundle", help="Path to proof_bundle directory")
    verify_p.set_defaults(func=_cmd_verify_attestation)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
