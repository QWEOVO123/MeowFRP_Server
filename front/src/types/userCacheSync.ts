export type CacheNodeState = {
  node_id: string
  node_name: string
  cached: boolean
  pending: boolean
  online: boolean
  applied_revision: number
  desired_revision: number
}
