# Releasing

Releases are published by `.github/workflows/release.yml` using **npm trusted publishing (OIDC)**. No npm token is created or stored, and npm generates provenance automatically.

## One-time setup

npm can only attach a trusted publisher to a package that already exists on the registry. The first version is therefore published once from your machine with your interactive npm login. That uses a short-lived session, not a token.

1. Enable two-factor authentication on your npm account (Account → Two-Factor Authentication). `npm trust` requires it.
2. Make sure `package.json` → `repository.url` points exactly at this GitHub repository (`git+https://github.com/ShambaC/anti-bla.git`). npm checks it during OIDC publishing.
3. Publish the first version locally. Provenance is only possible in CI, so turn it off for this one run:

   ```bash
   npm install --global npm@latest      # npm >= 11.15.0 for `npm trust`
   npm login                            # browser login with 2FA
   npm ci && npm test
   npm publish --access public --provenance=false
   ```

   Alternative, without a direct publish: run `npm stage publish --access public --provenance=false`, then `npm stage approve <stage-id>` (prompts for 2FA). New packages can be created through staged publishing as well.

4. Attach the trusted publisher. Use either the CLI:

   ```bash
   npm trust github anti-bla --file release.yml --repo ShambaC/anti-bla --env npm --allow-publish
   ```

   or the website: npmjs.com → `anti-bla` → Settings → Trusted Publisher → GitHub Actions. Fill in user `ShambaC`, repository `anti-bla`, workflow `release.yml`, environment `npm`, and allow `npm publish`.

   Use `--allow-stage-publish` instead if every CI release should wait for you to run `npm stage approve` with 2FA.

5. Lock the package down: npmjs.com → `anti-bla` → Settings → Publishing access → **Require two-factor authentication and disallow tokens**.
6. On GitHub, create the environment `npm` (Settings → Environments). Optionally add yourself as a required reviewer. No secrets are needed.

A new trusted-publisher configuration must complete a successful publish within **2 days** or it expires. Cut the next release soon after step 4.

## Every release

1. Bump `version` in `package.json`, `.claude-plugin/plugin.json` and `.codex-plugin/plugin.json` (the workflow fails if they differ from each other or from the tag).
2. Commit and push to `main`.
3. Create a GitHub Release with tag `vX.Y.Z` and publish it. The workflow runs typecheck, tests and the skill check, then runs `npm publish`, authenticated by OIDC.

To rehearse, run the workflow manually from the Actions tab (`dry_run: true`). It does everything except upload.

## Troubleshooting

- **`ENEEDAUTH` / 404 on publish:** the trusted-publisher fields do not match. Check the user/repo, the workflow **filename** `release.yml` (not its path), the environment `npm`, and that the package allows `npm publish`. npm does not validate these on save.
- **Errors that look like token problems:** check that the workflow upgraded npm (>= 11.5.1) and that the job has `permissions: id-token: write`.
- Self-hosted runners are not supported for trusted publishing. Use GitHub-hosted runners.
