# Prepare for Auto Upgrade Test

@ant-node/src/bin/antnode/main.rs
@ant-node/src/bin/antnode/upgrade/mod.rs
@release-cycle-info
@ant-build-info/src/release_info.rs

I want you to help me prepare for a test of the automatic-upgrades process.

The process has 2 phases: preparing the current branch for an auto-upgrade test, and preparing a new
branch with a fake release candidate.

So first, I need you to reduce the upgrade check time from 3 days to 30 minutes, and reduce the
randomness to 2 minutes. Now you need to make a change to the `fetch_and_cache_release_info`
function. Replace the usage of `release_repo.get_latest_autonomi_release_info` to
`release.get_autonomi_release_info`. This function takes a string, which is the tag of the fake
release that will be created. You need to prompt me for the name. Finally, we have code that
downloads the new binary from an `autonomi.com` URL and uses an S3 URL as a fallback. Another
temporary change is required here to just use the S3 URL directly, since the `autonomi.com` URL
always points to the latest release, which is not what we want for the test.

Once you've made that change, create a chore commit that indicates these are temporary changes that
will be removed. This commit then needs to be pushed to the origin on the current branch. However,
before you do this, let me review the diff first. Then you can push when I give the go ahead. If you
get an error, you most likely need to force push. This is fine.

Now the second phase.

First, I need you to create a new branch from the current one. Prompt me for the name of the new
branch. Second, I need you to run `cargo release version <version> --package ant-node --execute
--no-confirm`. For the version, you should get the current version of the `ant-node` crate, then
increment the `PATCH` component by 1, and also add the `rc.1` suffix. Third, I need you to update
the `release-cycle-info` and `ant-build-info/src/release_info.rs` files. The cycle counter value in
both of them needs to be incremented by 1.

With these changes, create a commit with the title `chore(release): release candidate
<release_year>.<release_month>.<release_cycle>.<release_cycle_counter>` and in the body, indicate
that it's a fake release candidate.

Allow me to review the commit, and once I approve, push the branch to the `upstream` remote.
