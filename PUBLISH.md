To publish a new version:

 1. Set `package.version` in `./Cargo.toml`
 2. Review and commit all changed files
 3. Raise a PR & Wait for CI
 4. Merge
 5. `cargo publish`
 6. Create a tag of the form `vX.Y.Z`: `git tag -m 'vX.Y.Z' && git push --tags`