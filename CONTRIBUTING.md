# Contributing to Kairos

Thanks for helping. The most valuable contribution right now needs no code at
all: **run a testnet node, keep it running, and report what goes wrong.**

## Reporting bugs

Use the **bug report** form under Issues. Include your Kairos version, what you
did, what happened and the log output. Security problems go through private
reporting instead; see [SECURITY.md](SECURITY.md).

## Changing code

1. Fork the repository and create a branch.
2. Make your change, and **add a test that fails without it**.
3. Run the whole suite with both signature backends:
   ```
   python -m unittest discover -s tests
   KAIROS_FORCE_PY_CRYPTO=1 python -m unittest discover -s tests
   ```
4. Open a pull request explaining what changed and why.

## Rules for consensus code

`params.py`, `tx.py`, `block.py`, `auxpow.py` and the validation parts of
`chain.py` decide which blocks are valid. A mistake there can split the
network, so changes to them need:

- a written rationale in the pull request;
- tests for both the accepted and the rejected case;
- agreement between the libsecp256k1 and pure-Python signature backends;
- review by at least one maintainer who didn't write the change.

Anything that changes which blocks are valid is a **fork** and must be
announced and scheduled, never slipped into an ordinary release.

## Style

- Standard library only, apart from the optional `coincurve` package.
- Clear code over clever code: this is also the readable reference implementation.
- Keep the whitepaper, the README and the code in agreement.

## Conduct

Be respectful and assume good faith. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
