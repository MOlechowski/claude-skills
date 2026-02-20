# Terraform Decision Trees

## Apply Decision Flow

```
Should I apply changes?
│
├─ Is this a PR/branch?
│  └─ YES → Plan only, post to PR comment
│
├─ Is this main/master branch?
│  ├─ Do I have a saved plan?
│  │  ├─ YES → Apply the saved plan
│  │  └─ NO → Generate plan first, review, then apply
│  │
│  └─ Is this production?
│     ├─ YES → Require manual approval
│     └─ NO → Auto-apply acceptable (with saved plan)
│
├─ Is this an emergency fix?
│  └─ YES → Plan → Review → Apply with explicit approval
│           Document the change for post-mortem
│
└─ Is this drift remediation?
   ├─ Accept real-world state → apply -refresh-only
   └─ Revert to config → apply (normal)
```

## Environment Selection

```
How should I organize environments?
│
├─ Are environments structurally similar?
│  │
│  ├─ YES (same resources, different scale)
│  │  └─ Use WORKSPACES
│  │     - Same .tf files
│  │     - Different .tfvars
│  │     - State per workspace
│  │
│  └─ NO (different resources per env)
│     └─ Use DIRECTORIES
│        - Separate .tf files per env
│        - Can share modules
│        - Explicit state per directory
│
├─ Do environments use different providers?
│  └─ YES → Use DIRECTORIES
│
├─ Do I need audit trails per environment?
│  └─ YES → Use DIRECTORIES (clearer git history)
│
└─ Am I prototyping quickly?
   └─ YES → Use WORKSPACES (faster iteration)
```

## Terraform Cloud Decision

```
Should I use Terraform Cloud?
│
├─ Team size > 2 people?
│  └─ YES → Consider TFC for collaboration
│
├─ Need policy enforcement?
│  └─ YES → TFC with Sentinel (Enterprise)
│
├─ Want automatic cost estimation?
│  └─ YES → TFC (built-in)
│
├─ Need centralized state management?
│  ├─ Self-manage → S3/GCS/Azure Blob backend
│  └─ Managed → Terraform Cloud
│
├─ VCS-driven workflow preferred?
│  └─ YES → TFC with VCS integration
│
└─ Budget constraints?
   ├─ Free tier sufficient → TFC Free (5 users)
   └─ Need more → TFC Teams/Enterprise or self-manage
```

## TFC Workspace Strategy

```
How should I organize TFC workspaces?
│
├─ One workspace per environment?
│  └─ production, staging, dev workspaces
│     Pro: Clear separation
│     Con: Code duplication
│
├─ One workspace with variable sets?
│  └─ Single workspace, different var values
│     Pro: DRY
│     Con: Risk of wrong env
│
└─ Recommended: Hybrid approach
   ├─ Separate workspaces per env
   ├─ Shared variable sets for common config
   └─ Tags for organization (app:web, env:prod)
```

## State Operation Decisions

```
Which state operation should I use?
│
├─ Resource needs to be renamed in code
│  └─ Use: terraform state mv old_name new_name
│     Then: Update .tf file to match
│     Verify: terraform plan shows no changes
│
├─ Resource was deleted outside Terraform
│  └─ Use: terraform state rm resource_name
│     This removes from state, no real deletion
│
├─ Resource exists but isn't in state
│  └─ Use: terraform import resource_type.name real_id
│     First: Add resource block to .tf
│     Verify: terraform plan shows no changes
│
├─ Need to move resource to different module
│  └─ Use: terraform state mv resource module.name.resource
│     Update: Move block to module in .tf
│
├─ Need to split state into multiple states
│  └─ Use: terraform state mv -state-out=new.tfstate resource
│     Warning: Coordinate with team
│
└─ State is corrupted
   └─ Restore: terraform state push backup.tfstate
      If no backup: Re-import all resources
```

## Backend Migration Decisions

```
How should I migrate backends?
│
├─ Local → Remote (S3, GCS, Azure)
│  │
│  ├─ 1. Add backend config to .tf
│  ├─ 2. Run: terraform init -migrate-state
│  ├─ 3. Verify: terraform plan shows no changes
│  └─ 4. Delete local terraform.tfstate
│
├─ Remote → Terraform Cloud
│  │
│  ├─ 1. terraform login
│  ├─ 2. Update to cloud block
│  ├─ 3. Run: terraform init -migrate-state
│  └─ 4. Verify in TFC UI
│
├─ Remote → Different Remote
│  │
│  ├─ 1. Update backend config
│  ├─ 2. Run: terraform init -migrate-state
│  └─ 3. Verify state in new location
│
├─ Remote → Local (rarely needed)
│  │
│  ├─ 1. Run: terraform state pull > terraform.tfstate
│  ├─ 2. Remove backend config
│  └─ 3. Run: terraform init
│
└─ Changing bucket/key within same backend
   │
   ├─ 1. Update backend config
   └─ 2. Run: terraform init -reconfigure
          (or -migrate-state if moving data)
```

## Error Recovery

```
What went wrong and how do I fix it?
│
├─ "State lock" error
│  │
│  ├─ Is someone else running Terraform?
│  │  └─ YES → Wait for them to finish
│  │
│  └─ Lock is stale (process crashed)?
│     └─ Run: terraform force-unlock LOCK_ID
│
├─ "Resource already exists" error
│  │
│  ├─ Resource was created manually
│  │  └─ Import: terraform import resource_type.name id
│  │
│  └─ State out of sync
│     └─ Refresh: terraform refresh
│
├─ Apply failed mid-way
│  │
│  ├─ Some resources created, some failed
│  │  └─ Fix error, re-run: terraform apply
│  │     Terraform will only create remaining
│  │
│  └─ Need to rollback
│     └─ Run: terraform destroy -target=created_resource
│        Or restore from backup state
│
├─ "Cycle detected" error
│  │
│  ├─ Review depends_on references
│  ├─ Remove circular dependencies
│  └─ Consider using data sources instead
│
├─ Provider authentication error
│  │
│  ├─ Check credentials (env vars, config files)
│  ├─ Verify IAM permissions
│  └─ Check region/project settings
│
├─ Terraform Cloud authentication
│  │
│  ├─ Run: terraform login
│  ├─ Or set TF_TOKEN_app_terraform_io
│  └─ Check team/workspace permissions
│
└─ "Inconsistent dependency lock file"
   └─ Run: terraform init -upgrade
```

## When to Use -target

```
Should I use -target?
│
├─ Is this an emergency requiring immediate fix?
│  └─ YES → Use -target for specific resource
│           Document and follow up with full apply
│
├─ Am I debugging a specific resource issue?
│  └─ YES → Use -target for investigation
│           Run full plan after debugging
│
├─ Am I trying to speed up a large apply?
│  └─ NO → Don't use -target
│           Risk of inconsistent state not worth it
│
└─ Am I avoiding changes to other resources?
   └─ NO → Don't use -target
           Fix the plan instead
           If changes are unexpected, investigate why
```

## Destroy Decisions

```
How should I handle destruction?
│
├─ Destroy everything
│  │
│  ├─ 1. Run: terraform plan -destroy
│  ├─ 2. Review carefully
│  ├─ 3. Run: terraform destroy
│  └─ 4. Verify empty state: terraform state list
│
├─ Destroy specific resource
│  │
│  ├─ 1. Run: terraform plan -destroy -target=resource
│  ├─ 2. Review dependencies
│  ├─ 3. Run: terraform destroy -target=resource
│  └─ Warning: May leave orphaned resources
│
├─ Remove resource from Terraform without destroying
│  │
│  ├─ 1. Remove from .tf file
│  ├─ 2. Run: terraform state rm resource
│  └─ Resource remains in cloud, unmanaged
│
└─ Destroy with plan file (safest)
   │
   ├─ 1. Run: terraform plan -destroy -out=destroy.tfplan
   ├─ 2. Review: terraform show destroy.tfplan
   └─ 3. Apply: terraform apply destroy.tfplan
```

## Module Decisions

```
When should I create a module?
│
├─ Is this code reused in multiple places?
│  └─ YES → Create a module
│
├─ Is the code complex enough to benefit from abstraction?
│  └─ YES → Create a module
│
├─ Will different teams use this?
│  └─ YES → Create a module with clear interface
│
└─ Am I just organizing code?
   └─ NO → Keep it simple, don't over-modularize
           1-2 uses: inline code is fine
           3+ uses: consider a module
```

## Versioning Decisions

```
How should I version modules?
│
├─ Using Git source
│  │
│  ├─ Explicit tag: ?ref=v1.2.3 (recommended)
│  ├─ Branch: ?ref=main (risky for production)
│  └─ Commit: ?ref=abc123 (specific but opaque)
│
├─ Using registry
│  │
│  ├─ Exact: version = "1.2.3"
│  ├─ Pessimistic: version = "~> 1.2" (any 1.2.x)
│  └─ Range: version = ">= 1.0, < 2.0"
│
└─ Production environments
   └─ Always use exact versions or explicit tags
      Never use "latest" or branch references
```

## Workspace vs Directory Quick Decision

| Question | Workspace | Directory |
|----------|-----------|-----------|
| Same infra, different sizes? | Yes | |
| Different infra per env? | | Yes |
| Different providers? | | Yes |
| Need strict isolation? | | Yes |
| Rapid iteration? | Yes | |
| Audit requirements? | | Yes |
| Team manages separately? | | Yes |
| Single CI pipeline? | Yes | |

## Terraform Cloud vs Self-Managed

| Factor | Terraform Cloud | Self-Managed |
|--------|-----------------|--------------|
| State storage | Managed | S3/GCS/Azure |
| State locking | Automatic | DynamoDB/etc |
| Remote execution | Built-in | CI/CD |
| Cost estimation | Built-in | External |
| Policy (Sentinel) | Enterprise | External |
| Team management | Built-in | IAM |
| Audit logs | Built-in | CloudTrail |
| Cost | Free tier / paid | Infrastructure |

## Safety Checklist

Before applying to production:

- [ ] Plan saved to file (`-out=plan.tfplan`)
- [ ] Plan reviewed by second person
- [ ] No unexpected destroys in plan
- [ ] No sensitive data in outputs
- [ ] Resource counts look reasonable
- [ ] State backed up (`state pull > backup.tfstate`)
- [ ] Lock mechanism verified
- [ ] Rollback plan documented
- [ ] Monitoring in place
- [ ] Communication sent to stakeholders

### Terraform Cloud Additional Checks

- [ ] Sentinel policies passing
- [ ] Cost estimate reviewed
- [ ] Workspace variables correct
- [ ] Run confirmed in UI (if required)
