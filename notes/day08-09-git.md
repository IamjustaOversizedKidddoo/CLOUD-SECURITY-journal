# Days 08–09 — Git Architecture, Commit Signing, SSH Keys & Pull Request Security

## 1. Executive Summary & Core Mechanics

In modern DevSecOps and cloud security engineering, Git is not merely a developer collaboration tool; it is the **authoritative entry point for all infrastructure and deployment pipelines**. Every Terraform template, AWS IAM policy, Kubernetes manifest, and container definition is committed to Git. Consequently, Git repositories are primary targets for credential exfiltration, pipeline poisoning, and unauthorized code insertion.

---

### 1. Git Architecture: Directed Acyclic Graph (DAG) & Content-Addressing
Git is a distributed, content-addressable storage system that models history as a **Directed Acyclic Graph (DAG)** of immutable objects stored under `.git/objects`:

1. **Blobs:** Store raw file contents (independent of file names or permissions).
2. **Trees:** Represent directory listings, mapping filenames and file modes to blob hashes or sub-trees.
3. **Commits:** Permanent snapshots pointing to a top-level Tree object, containing:
   * Parent commit hash(es)
   * Author and Committer identity (name, email, timestamp)
   * Commit message
   * PGP signature (if commit signing is enabled)

```text
Commit A (Hash: e4a1...) <--- Commit B (Hash: c8b2...) <--- HEAD / main (Hash: f906...)
    |                             |
  Tree (root)                   Tree (root)
  ├── file1 (Blob 1)            ├── file1 (Blob 1 - unchanged)
  └── config (Blob 2)           └── config (Blob 3 - updated)
```

#### What a Commit Hash Actually Represents:
A commit hash (traditionally 40-character SHA-1, transitioning to SHA-256) is a cryptographic hash of the commit object's entire contents, including its tree and parent hash. 
* **Tamper-Evidence:** Because each commit cryptographically references its parent, altering a single character in past code changes that commit's hash. This cascades forward, invalidating all subsequent commit hashes in the chain. This provides cryptographic verification that history has not been silently rewritten.

---

### 2. The Staging Area (Index) & Atomic Commits
Git separates the **Working Directory**, the **Staging Area (Index)**, and the **Repository Database (`.git`)**:
* `git add` moves specific, intentional modifications into the Staging Area.
* `git commit` bundles what is currently staged into an atomic snapshot.
* **Security Importance:** This separation prevents accidental leakage. Engineers can review diffs (`git diff --staged`) before freezing them into history, ensuring temporary debug logs, local test credentials, or unwanted files never enter the commit graph.

---

### 3. Branches & Pull Requests as Security Gates
* **Branches:** A branch is not a duplicated folder; it is a lightweight 41-byte pointer containing the SHA hash of the latest commit on that lineage.
* **Pull Requests (PRs) as Security Controls:** A PR is a formal control plane before code merges into protected branches (`main`/`production`):
  * **Peer Code Review:** Requires a second authorized engineer to inspect the diff for security vulnerabilities or logical flaws.
  * **Automated CI/CD Scans:** Runs SAST (Static Application Security Testing) and secret detection tools (`gitleaks`, `trufflehog`) automatically on the branch diff.
  * **Auditability & Non-Repudiation:** Merged PRs link code changes to approval discussions, testing results, and reviewer signatures.

---

### 4. SSH Key Isolation: GitHub vs. Infrastructure
* **The Vulnerability of Shared Keys:** Using the same private key (`~/.ssh/id_rsa`) for both GitHub authentication and server SSH access creates an unnecessary blast-radius catastrophe.
* **The Least-Privilege Model:** Generate isolated keypairs per operational domain:
  * `~/.ssh/github_ed25519`: Scoped strictly to Git repository hosting.
  * `~/.ssh/aws_ec2_ed25519`: Scoped strictly to bastion/host infrastructure.
  * If the workstation's GitHub key is leaked, an adversary cannot pivot to establish remote shell sessions on cloud servers.

---

## 2. Break It Safely: The Leaked Secret Experiment

### The Controlled Test:
We generated a temporary repository, committed an AWS secret credential, deleted the file in a second commit, and checked whether the secret was removed from Git.

```bash
# 1. Commit sensitive credential
echo "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE_SECRET_LEAKED_123456789" > fake_aws_creds.txt
git add fake_aws_creds.txt
git commit -m "feat: add config file with credentials"

# 2. "Delete" the file in a follow-up commit
rm fake_aws_creds.txt
git add fake_aws_creds.txt
git commit -m "fix: delete exposed credentials file"
```

### Forensic Investigation of History:
Running `git log` across all history:
```bash
git log --all --full-history --oneline -- fake_aws_creds.txt
```
**Output:**
```text
f9069ea fix: delete exposed credentials file
cddb657 feat: add config file with credentials
```

Extracting the "deleted" file directly from past commit `cddb657`:
```bash
git show cddb657:fake_aws_creds.txt
```
**Output:**
```text
AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE_SECRET_LEAKED_123456789
```

### Why `git rm` Completely Fails as a Security Fix:
Commits in Git are **immutable snapshots**. When a file is deleted in a new commit, Git creates a new Tree object that simply omits that filename. The prior commit and its underlying Blob object remain intact, permanently stored in `.git/objects`. Anyone who clones the repository can inspect past commits and extract the cleartext secret in seconds.

---

## 3. Fix It: The Secret Leakage Incident Response Hierarchy

If an AWS key or sensitive credential is accidentally pushed to a remote repository, follow this strict 4-step remediation hierarchy:

```mermaid
graph TD
    A["<b>Step 1: Immediate Invalidation & Rotation</b><br>(Assume compromised immediately; revoke IAM key in AWS Console/CLI)"] --> B["<b>Step 2: CloudTrail Forensic Audit</b><br>(Review API calls made with the compromised AccessKeyId during the exposure window)"]
    B --> C["<b>Step 3: History Scrubbing</b><br>(Use git-filter-repo or BFG to permanently delete the blob across all commits)"]
    C --> D["<b>Step 4: Force-Push & Cache Invalidation</b><br>(Force-push scrubbed refs and notify all developers to re-clone)"]
```

1. **Step 1: Invalidate and Rotate the Credential Immediately (Non-Negotiable):**
   * The moment a commit is pushed to a remote server, automated internet scrapers and botnets harvest the key within milliseconds.
   * Immediately deactivate or delete the access key in the AWS IAM Console (`aws iam update-access-key --status Inactive`). Never waste time attempting to clean Git history before revoking the credential!
2. **Step 2: Forensic CloudTrail Audit:**
   * Query AWS CloudTrail Event History filtering by `accessKeyId`:
     ```bash
     aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE
     ```
   * Determine whether unauthorized resources (e.g., rogue EC2 crypto-miners, new IAM users) were provisioned during the exposure window.
3. **Step 3: Git History Purging:**
   * Remove the blob permanently from all historical commits using modern tooling:
     ```bash
     git-filter-repo --invert-paths --path fake_aws_creds.txt
     ```
   * *Note:* Avoid the deprecated `git filter-branch` due to slowness and edge-case corruption risks.
4. **Step 4: Force-Push & Upstream Invalidation:**
   * Force-push updated branches: `git push origin --force --all`.
   * Contact GitHub Support to flush cached pull request views and dangling commit caches.

---

## 4. GitHub Enterprise Security Controls

To convert a repository from a simple code host into a compliant DevSecOps pipeline, configure these repository settings:

1. **Branch Protection Rules (`main` branch):**
   * **Require a pull request before merging:** Prevents direct commits or bypasses.
   * **Require approvals:** Enforces minimum 1–2 peer sign-offs.
   * **Require status checks to pass:** Blocks merges until automated test suites, linting, and security scans pass.
   * **Require signed commits:** Mandates GPG/SSH cryptographic commit signatures (`git commit -S`) to verify author authenticity.
   * **Do not allow bypassing the above settings:** Enforces rules equally on administrators.
2. **Automated Secret Scanning & Push Protection:**
   * Enable GitHub Secret Scanning and **Push Protection**. Push Protection actively intercepts `git push` operations if high-entropy strings matching known vendor formats (AWS, Stripe, Slack) are detected, rejecting the push *before* the remote repository accepts the objects.

---

## 5. Interview Questions & Model Answers

### Beginner:
1. **What is the difference between `git add` and `git commit`?**  
   *Answer:* `git add` moves specific working directory modifications into the Staging Area (Index), allowing fine-grained selection of changes. `git commit` bundles whatever is currently in the Staging Area into a permanent, immutable snapshot with author metadata and a cryptographic commit hash.

2. **What is a branch technically (not "a copy of the code")?**  
   *Answer:* Technically, a branch in Git is simply a lightweight, movable pointer (stored as a 41-byte text file in `.git/refs/heads/`) that contains the 40-character SHA hash of the most recent commit on that lineage.

3. **What is the difference between core Git and a GitHub Pull Request?**  
   *Answer:* Git is a decentralized command-line version control engine focused on tracking history and merging branches locally. A Pull Request is a collaborative, web-based platform feature provided by GitHub that acts as a governance gate, providing a centralized interface for peer code review, automated CI/CD security scanning, and policy enforcement before merging into a target branch.

### Intermediate:
4. **Why doesn't deleting a file in a new commit remove it from a repo's history?**  
   *Answer:* Git's data model is an append-only directed acyclic graph of immutable snapshots. When a file is deleted, Git merely creates a new commit pointing to a new tree that omits that filename. All historical commits and their underlying blob objects remain permanently stored in `.git/objects` and can be reconstructed using `git show` or `git checkout`.

5. **What is the security purpose of requiring Pull Request reviews before merging to `main`?**  
   *Answer:* It enforces separation of duties and dual-control authorization. Requiring peer reviews ensures that malicious code injections, accidental syntax mistakes, architectural misconfigurations, and hardcoded secrets are caught by an independent engineer before software is deployed into production.

6. **Why should you use a separate SSH key for GitHub versus server access?**  
   *Answer:* To enforce the Principle of Least Privilege and minimize blast radius. If a laptop or GitHub key is compromised, an attacker only gains repository access. If that same key was shared with production EC2 instances, the attacker would simultaneously compromise server shell access.

### Scenario-Based:
7. **A developer accidentally pushes an AWS secret key to a public GitHub repo, notices 10 minutes later, and deletes the file in a follow-up commit. Walk through your actions in order.**  
   *Answer:*
   1. **Immediate Revocation:** Assume the key was harvested within seconds. Immediately log into AWS IAM and deactivate/delete the exposed `AccessKeyId`.
   2. **Audit CloudTrail:** Query CloudTrail for all API activity associated with that key during the exposure window to identify unauthorized actions.
   3. **Scrub Git History:** Use `git-filter-repo` or BFG to excise the credential blob from all commit history.
   4. **Force-Push & Clear Caches:** Force-push the scrubbed history to GitHub and open a ticket with GitHub Support to clear cached commit views.
   5. **Root-Cause Prevention:** Install pre-commit secret scanning hooks (`gitleaks`) on developer machines and enable GitHub Push Protection.

8. **You are setting up a new repository for a security-sensitive project. What GitHub-level controls do you configure?**  
   *Answer:*
   * Enable Branch Protection on `main` requiring approved PR reviews and passing CI status checks.
   * Enable GitHub Secret Scanning and Push Protection.
   * Enforce GPG/SSH commit signature verification.
   * Disable force-pushes and branch deletions.
   * Restrict repository access permissions via GitHub Teams adhering to least privilege.
   * Configure Dependabot automated alerts and security updates for vulnerable dependencies.

### Difficult:
9. **Explain why a commit hash is described as "content-addressed" and what security property that provides.**  
   *Answer:* Content-addressing means data is retrieved and indexed based on a cryptographic hash of its exact contents rather than an arbitrary filename or location. In Git, every blob, tree, and commit hash is generated by hashing its underlying bytes (including parent hashes and metadata). This provides **tamper-evident integrity**: it is computationally infeasible to alter historical code or metadata without changing the resulting hash, which immediately invalidates all child commits and alerts collaborators to unauthorized tampering.

---

## 6. Mini Assessment Self-Check
- [x] **What `git push` actually does:** Transmits local commit objects, trees, and blobs to the remote repository and updates the remote branch pointer (e.g., `refs/remotes/origin/main`) to match the local branch reference.
- [x] **Why Ed25519 is preferred over RSA:** Ed25519 offers stronger security margins, superior resistance to side-channel attacks, smaller key sizes (68 characters vs. 2048+ bit RSA), and substantially faster signature generation and verification.
- [x] **GitHub feature enforcing PR review:** **Branch Protection Rules** (specifically *"Require a pull request before merging"* with *"Require approvals"*).
- [x] **Deleting a secret in a file True/False:** **False.** Deleting a file in a subsequent commit only removes it from the current and future snapshots; all prior commit objects retain the cleartext blob in `.git/objects`.
- [x] **PR review finding hardcoded password:** Reject the PR immediately and inform the developer that the password must be rotated in the database right away. Even if removed from the PR branch before merging, the secret has already been pushed to GitHub's remote servers and stored in the commit graph, rendering it compromised.
