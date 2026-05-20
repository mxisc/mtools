/* eslint-disable @typescript-eslint/no-explicit-any */

declare global {
  interface Window {
    runtime: {
      GoCall: (receiver: string, method: string, ...args: any[]) => Promise<any>
      EventsOn: (eventName: string, callback: (...args: any[]) => void) => void
      EventsOff: (eventName: string) => void
    }
    go: {
      main: {
        App: {
          GetAppName: () => Promise<string>
          IsRunning: () => Promise<boolean>
          StopTask: () => Promise<void>
          RunWebCheck: (target: string) => Promise<any>
          RunPortScan: (
            host: string,
            startPort: number,
            endPort: number,
            workers: number,
            timeoutMs: number
          ) => Promise<any>
        }
      }
      wailsapp: {
        App: {
          GetAppName: () => Promise<string>
          IsRunning: () => Promise<boolean>
          StopTask: () => Promise<void>
          RunWebCheck: (target: string) => Promise<any>
          RunPortScan: (
            host: string,
            startPort: number,
            endPort: number,
            workers: number,
            timeoutMs: number,
            ipVersion: string
          ) => Promise<any>
        }
      }
    }
  }
}

function getApp(): any {
  return window.go?.main?.App || window.go?.wailsapp?.App
}

export function isWailsAvailable(): boolean {
  return !!getApp()
}

export async function getAppName(): Promise<string> {
  const app = getApp()
  if (app) {
    return await app.GetAppName()
  }
  return 'PortDesk'
}

export async function isRunning(): Promise<boolean> {
  const app = getApp()
  if (app) {
    return await app.IsRunning()
  }
  return false
}

export async function stopTask(): Promise<void> {
  const app = getApp()
  if (app) {
    await app.StopTask()
  }
}

export async function runWebCheck(target: string): Promise<any> {
  const app = getApp()
  if (!app) {
    throw new Error('Wails 后端未连接，请使用已编译的应用运行')
  }
  return await app.RunWebCheck(target)
}

export async function runPortScan(
  host: string,
  startPort: number,
  endPort: number,
  workers: number,
  timeoutMs: number,
  ipVersion: string
): Promise<any> {
  const app = getApp()
  if (!app) {
    throw new Error('Wails 后端未连接，请使用已编译的应用运行')
  }
  return await app.RunPortScan(
    host,
    startPort,
    endPort,
    workers,
    timeoutMs,
    ipVersion
  )
}

export function onPortScanProgress(callback: (data: any) => void): void {
  if (window.runtime?.EventsOn) {
    window.runtime.EventsOn('portscan:progress', callback)
  }
}

export function offPortScanProgress(): void {
  if (window.runtime?.EventsOff) {
    window.runtime.EventsOff('portscan:progress')
  }
}

export function onWebCheckProgress(callback: (data: any) => void): void {
  if (window.runtime?.EventsOn) {
    window.runtime.EventsOn('webcheck:progress', callback)
  }
}

export function offWebCheckProgress(): void {
  if (window.runtime?.EventsOff) {
    window.runtime.EventsOff('webcheck:progress')
  }
}

export {}
