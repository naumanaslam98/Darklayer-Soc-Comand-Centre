# Contributing

Thank you for improving DarkLayer SOC Center.

## Local development

1. Fork or clone the repository.
2. Run `python3 scripts/generate_env.py` to create a local Git-ignored `.env`.
3. Run `./run_local.sh`.
4. Make focused changes and add or update tests.
5. Run:

```bash
python -m compileall -q app scripts tests
python tests/smoke_test.py
python tests/live_stream_test.py
```

## Pull requests

Keep pull requests focused and describe:

- the problem being solved;
- security or privacy implications;
- how the change was tested;
- any configuration or migration impact.

Never commit real `.env` files, credentials, API keys, SMTP passwords, telemetry databases, or personal logs.
