// Local PoC for the project-scope gap in supabase/mcp's branch tools, tracked upstream
// in public PR supabase/mcp#351. Runs against the repo's mocked Management API only;
// it never contacts Supabase. Copy to packages/mcp-server-supabase/src/ to run.
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import {
  createBranch,
  createOrganization,
  createProject,
  mockBranches,
} from '../test/mocks.js';
import { createServerHarness } from '../test/server-harness.js';

const harness = createServerHarness();
const setup = harness.setup;

beforeEach(() => harness.reset());
afterEach(() => harness.close());

async function twoProjects() {
  const org = await createOrganization({
    name: 'Org',
    plan: 'free',
    allowed_release_channels: ['ga'],
  });
  const projectA = await createProject({
    name: 'Project A',
    region: 'us-east-1',
    organization_id: org.id,
  });
  const projectB = await createProject({
    name: 'Project B',
    region: 'us-east-1',
    organization_id: org.id,
  });
  const foreign = await createBranch({
    name: 'project-b-branch',
    parent_project_ref: projectB.id,
  });
  return { projectA, projectB, foreign };
}

const branchExists = (id: string) =>
  [...mockBranches.values()].some((branch) => branch.id === id);

describe('server scoped to Project A', () => {
  test('control: list_branches does not show the Project B branch', async () => {
    const { projectA, foreign } = await twoProjects();
    const { callTool } = await setup({ projectId: projectA.id });
    const result = await callTool({ name: 'list_branches', arguments: {} });
    expect(result.branches.map((b: { id: string }) => b.id)).not.toContain(
      foreign.id
    );
  });

  test('control: a project_id argument is rejected', async () => {
    const { projectA, projectB } = await twoProjects();
    const { callTool } = await setup({ projectId: projectA.id });
    await expect(
      callTool({
        name: 'list_branches',
        arguments: { project_id: projectB.id },
      })
    ).rejects.toThrow();
  });

  test('control: account-level tools are unavailable', async () => {
    const { projectA, projectB } = await twoProjects();
    const { callTool } = await setup({ projectId: projectA.id });
    await expect(
      callTool({ name: 'get_project', arguments: { id: projectB.id } })
    ).rejects.toThrow();
  });

  test('control: read-only mode blocks delete_branch', async () => {
    const { projectA, foreign } = await twoProjects();
    const { callTool } = await setup({
      projectId: projectA.id,
      readOnly: true,
    });
    await expect(
      callTool({ name: 'delete_branch', arguments: { branch_id: foreign.id } })
    ).rejects.toThrow();
    expect(branchExists(foreign.id)).toBe(true);
  });

  test('POC: delete_branch removes a Project B branch', async () => {
    const { projectA, foreign } = await twoProjects();
    const { callTool } = await setup({ projectId: projectA.id });
    expect(branchExists(foreign.id)).toBe(true);
    await callTool({
      name: 'delete_branch',
      arguments: { branch_id: foreign.id },
    });
    expect(branchExists(foreign.id)).toBe(false);
  });

  test('POC: merge, reset and rebase accept a Project B branch', async () => {
    const { projectA, foreign } = await twoProjects();
    const { callTool } = await setup({ projectId: projectA.id });
    for (const [name, args] of [
      ['merge_branch', {}],
      ['reset_branch', {}],
      ['rebase_branch', {}],
    ] as const) {
      const outcome = await callTool({
        name,
        arguments: { branch_id: foreign.id, ...args },
      }).then(
        () => 'accepted',
        (error: Error) => `rejected: ${error.message}`
      );
      console.log(`${name} on Project B branch -> ${outcome}`);
      expect(outcome).toBe('accepted');
    }
  });
});
