# To Do

## Tasks

- [x] Obtain repo in BBVA's GitHub org (request to LEGAL dept.)
- [x] git filter-branch pancho's email
- [x] Add legal headers to code files
- [x] Move repo to BBVA's
- [x] Build a static release and publish it (this enables us to show it around)
- [x] Integrate tool with Patton
- [x] Build a pipeline to build the tool
- [x] Build a pipeline for publishing GENERIC and any other release
- [ ] Document usage so that we can communicate with Ubuntu
- [ ] Contact Ubuntu and introduce the prj to them
- [ ] Cleanup: Move things around to improve readability
- [x] Cleanup: purge unused code from the PoC
- [ ] Implement Sources section
- [ ] Implement CVSS parser and maybe contribute it to the Haskell community
- [ ] Try to ensure a smooth out-of-the-box experience for ubuntu users of Debsecan (possibly requesting Ubuntu with a PR)
- [ ] Profit!


## Possible Adoption by the Community

They have a [decade-old issue][IILF] still open.

[IILF]: https://bugs.launchpad.net/ubuntu/+source/debsecan/+bug/95925


### Ideal Scenario

- Ubuntu adopts this trasformer and integrates it into its security pipeline to
  produce the required databases.

  This scenario seems quite future-proof to us.


### Suboptimal Scenario

- Ubuntu does not accept this converter nor enhancing their pipeline with it
  In this case we would provide a container with the necessary elements to
  produce the report ourselves.