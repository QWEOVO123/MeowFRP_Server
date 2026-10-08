import { createRouter, createWebHistory, type RouteLocationNormalized, type RouteLocationRaw } from 'vue-router'
import PanelPage from './pages/PanelPage.vue'

export const panelPaths = {
  overview: '/panel/overview', users: '/panel/users', clients: '/panel/clients',
  clientHistory: '/panel/client-history', connections: '/panel/connections', bans: '/panel/bans',
  bootstrap: '/panel/bootstrap', nodes: '/panel/nodes', settings: '/panel/settings',
  dpi: '/panel/dpi', advanced: '/panel/settings/advanced',
} as const
export type PanelNav = keyof typeof panelPaths
export const panelSession = { ready: false, initialized: false, databaseReady: false, authed: false, edge: false }
const sections = ':section(frp|timeouts|tcp|mtls|file)?'
const advancedPage = () => import('./pages/AdvancedSettingsPage.vue')

export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { path: '/', redirect: panelPaths.overview },
    { path: '/index.html', redirect: panelPaths.overview },
    { path: '/panel', redirect: panelPaths.overview },
    { path: '/login', name: 'login', component: PanelPage },
    { path: '/setup', name: 'setup', component: PanelPage },
    { path: '/database-repair', name: 'repair', component: PanelPage },
    ...Object.entries(panelPaths).filter(([id]) => id !== 'advanced').map(([id, path]) => ({
      path, name: id, component: PanelPage,
      meta: { nav: id, requiresAuth: true, controllerOnly: !['overview', 'nodes', 'settings'].includes(id) },
    })),
    { path: `${panelPaths.advanced}/${sections}`, name: 'advanced', component: advancedPage, meta: { nav: 'advanced', requiresAuth: true, advanced: true } },
    { path: `/panel/nodes/:nodeID/settings/advanced/${sections}`, name: 'edge-advanced', component: advancedPage, meta: { nav: 'nodes', requiresAuth: true, controllerOnly: true, advanced: true } },
    { path: '/:pathMatch(.*)*', name: 'not-found', component: PanelPage, meta: { nav: 'not-found' } },
  ],
  scrollBehavior(to, from, saved) {
    if (saved) return saved
    if (to.name === from.name && to.params.nodeID === from.params.nodeID && to.meta.advanced) return false
    return { top: 0 }
  },
})

function returnTarget(to: RouteLocationNormalized): string {
  const candidate = to.query.redirect
  if (typeof candidate === 'string' && candidate.startsWith('/panel/')) {
    const resolved = router.resolve(candidate)
    if (resolved.meta.requiresAuth && (!panelSession.edge || !resolved.meta.controllerOnly)) return resolved.fullPath
  }
  return panelPaths.overview
}

export function panelRedirect(to: RouteLocationNormalized): RouteLocationRaw | undefined {
  if (!panelSession.ready) return
  const query = to.meta.requiresAuth ? { redirect: to.fullPath } : to.query
  if (!panelSession.initialized) return to.name === 'setup' ? undefined : { name: 'setup', query }
  if (!panelSession.databaseReady) return to.name === 'repair' ? undefined : { name: 'repair', query }
  if (!panelSession.authed) return to.name === 'login' ? undefined : { name: 'login', query }
  if (to.name === 'login' || to.name === 'setup' || to.name === 'repair') return returnTarget(to)
  if (panelSession.edge && to.meta.controllerOnly) return panelPaths.overview
}
router.beforeEach(panelRedirect)
