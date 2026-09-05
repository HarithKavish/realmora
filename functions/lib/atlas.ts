/**
 * MongoDB Atlas Admin API v2, called with a friend's own Service Account.
 *
 * NOT independently tested against a live Atlas project -- there is no Atlas
 * account available in this environment to provision against. Request
 * shapes below are taken from MongoDB's own docs (see the comments beside
 * each), but MongoDB has been moving free-tier clusters from the classic
 * "tenant" (M0) shape toward a newer "Flex" cluster API; if a friend's org
 * has been migrated, `createCluster` below may need to target
 * `/flexClusters` instead of `/clusters`. Verify against a real account
 * before relying on this.
 */
import type { Env } from "./env";
import { decryptSecret } from "./crypto";

const TOKEN_URL = "https://cloud.mongodb.com/api/oauth/token";
const API_BASE = "https://cloud.mongodb.com/api/atlas/v2";
// Versioned resource media type Atlas requires on every request (406 without
// it). 2023-01-01 is the version vector search shipped under.
const API_VERSION = "application/vnd.atlas.2023-01-01+json";

const DATABASE_NAME = "realmora";
const COLLECTION_NAME = "agent_memories";
const INDEX_NAME = "vector_index";
const CLUSTER_NAME = "realmora";
// MiniLM/bge-small-class embedding dimension. This is a placeholder until an
// embedding provider is actually chosen for agent memory -- changing it
// after documents exist means rebuilding the index and re-embedding
// everything, the same lesson Jarvis's own Atlas migration learned the hard
// way (same dimension count is not the same vector space).
const VECTOR_DIMENSIONS = 384;

async function getAccessToken(clientId: string, clientSecret: string): Promise<string> {
  const basic = btoa(`${clientId}:${clientSecret}`);
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      authorization: `Basic ${basic}`,
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: "grant_type=client_credentials",
  });
  if (!response.ok) {
    throw new Error(`Atlas token exchange failed: HTTP ${response.status}`);
  }
  const data = (await response.json()) as { access_token: string };
  return data.access_token;
}

async function atlasFetch(token: string, path: string, init?: RequestInit): Promise<Response> {
  const headers: Record<string, string> = {
    authorization: `Bearer ${token}`,
    accept: API_VERSION,
  };
  if (init?.body) headers["content-type"] = API_VERSION;
  return fetch(`${API_BASE}${path}`, { ...init, headers: { ...headers, ...init?.headers } });
}

interface ClusterState {
  stateName: "IDLE" | "CREATING" | "UPDATING" | "DELETING" | "REPAIRING";
}

async function getClusterState(token: string, projectId: string): Promise<ClusterState | null> {
  const response = await atlasFetch(token, `/groups/${projectId}/clusters/${CLUSTER_NAME}`);
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`Atlas: could not read cluster state (HTTP ${response.status})`);
  return response.json();
}

async function createCluster(token: string, projectId: string): Promise<void> {
  // Smallest free-tier ("tenant") shape. See file-level note: if this 404s
  // or 400s against a migrated org, the equivalent Flex-cluster endpoint
  // (`/groups/{projectId}/flexClusters`) needs a near-identical body.
  const response = await atlasFetch(token, `/groups/${projectId}/clusters`, {
    method: "POST",
    body: JSON.stringify({
      name: CLUSTER_NAME,
      clusterType: "REPLICASET",
      replicationSpecs: [
        {
          numShards: 1,
          providerSettings: {
            providerName: "TENANT",
            backingProviderName: "AWS",
            regionName: "US_EAST_1",
            instanceSizeName: "M0",
          },
        },
      ],
    }),
  });
  // 409 means it already exists (a concurrent request, or a retry after a
  // partial success) -- fine, not an error.
  if (!response.ok && response.status !== 409) {
    const detail = await response.text().catch(() => "");
    throw new Error(`Atlas: cluster creation failed (HTTP ${response.status}): ${detail}`);
  }
}

async function vectorIndexExists(token: string, projectId: string): Promise<boolean> {
  const response = await atlasFetch(
    token,
    `/groups/${projectId}/clusters/${CLUSTER_NAME}/search/indexes/${DATABASE_NAME}/${COLLECTION_NAME}`,
  );
  if (response.status === 404) return false;
  if (!response.ok) throw new Error(`Atlas: could not list search indexes (HTTP ${response.status})`);
  const indexes = (await response.json()) as Array<{ name: string }>;
  return indexes.some((index) => index.name === INDEX_NAME);
}

async function createVectorIndex(token: string, projectId: string): Promise<void> {
  const response = await atlasFetch(token, `/groups/${projectId}/clusters/${CLUSTER_NAME}/search/indexes`, {
    method: "POST",
    body: JSON.stringify({
      name: INDEX_NAME,
      type: "vectorSearch",
      database: DATABASE_NAME,
      collectionName: COLLECTION_NAME,
      fields: [
        { type: "vector", path: "embedding", numDimensions: VECTOR_DIMENSIONS, similarity: "cosine" },
        // Every agent's memories share this one index (Atlas free tier caps
        // out at 3 search indexes per cluster); pre-filtering on agentId is
        // what keeps one agent's memories out of another's search results.
        { type: "filter", path: "agentId" },
      ],
    }),
  });
  if (!response.ok && response.status !== 409) {
    const detail = await response.text().catch(() => "");
    throw new Error(`Atlas: index creation failed (HTTP ${response.status}): ${detail}`);
  }
}

export interface AtlasStatus {
  status: "not_connected" | "creating" | "ready";
  detail?: string;
}

/**
 * Advances Atlas provisioning by exactly one step and reports where things
 * stand. Cluster creation takes real minutes, so this is meant to be called
 * from a poll (e.g. every few seconds from the settings page) rather than
 * awaited to completion in one request -- a Worker cannot block that long
 * anyway.
 */
export async function advanceAtlasProvisioning(env: Env, userId: string): Promise<AtlasStatus> {
  const existing = await env.DB.prepare("SELECT 1 FROM atlas_connections WHERE user_id = ?").bind(userId).first();
  if (existing) return { status: "ready" };

  const cred = await env.DB
    .prepare("SELECT ciphertext, iv, client_id, metadata FROM credentials WHERE user_id = ? AND provider = 'atlas'")
    .bind(userId)
    .first<{ ciphertext: string; iv: string; client_id: string | null; metadata: string | null }>();
  if (!cred || !cred.client_id || !cred.metadata) {
    return { status: "not_connected", detail: "connect an Atlas Service Account and project id first" };
  }

  const projectId = (JSON.parse(cred.metadata) as { projectId?: string }).projectId;
  if (!projectId) return { status: "not_connected", detail: "no Atlas project id on file" };

  const clientSecret = await decryptSecret({ ciphertext: cred.ciphertext, iv: cred.iv }, env.CREDENTIALS_ENCRYPTION_KEY);
  const token = await getAccessToken(cred.client_id, clientSecret);

  const cluster = await getClusterState(token, projectId);
  if (!cluster) {
    await createCluster(token, projectId);
    return { status: "creating", detail: "cluster requested" };
  }
  if (cluster.stateName !== "IDLE") {
    return { status: "creating", detail: `cluster is ${cluster.stateName}` };
  }

  if (!(await vectorIndexExists(token, projectId))) {
    await createVectorIndex(token, projectId);
    return { status: "creating", detail: "vector index requested" };
  }

  await env.DB.prepare(
    `INSERT INTO atlas_connections (user_id, project_id, cluster_name, database_name, collection_name, index_name, provisioned_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(userId, projectId, CLUSTER_NAME, DATABASE_NAME, COLLECTION_NAME, INDEX_NAME, Date.now())
    .run();

  return { status: "ready" };
}
