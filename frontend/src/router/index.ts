import { createRouter, createWebHashHistory } from 'vue-router'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/',
      name: 'home',
      component: () => import('@/views/HomeView.vue'),
    },
    {
      path: '/webcheck',
      name: 'webcheck',
      component: () => import('@/views/WebCheckView.vue'),
    },
    {
      path: '/portscan',
      name: 'portscan',
      component: () => import('@/views/PortScanView.vue'),
    },
  ],
})

export default router
