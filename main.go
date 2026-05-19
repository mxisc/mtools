package main

import (
	"embed"
	"log"

	"portdesk/internal/wailsapp"

	wails "github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := wailsapp.NewApp()

	err := wails.Run(&options.App{
		Title:     "PortDesk",
		Width:     1280,
		Height:    800,
		MinWidth:  900,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.Startup,
		OnShutdown:       app.Shutdown,
		Bind: []any{
			app,
		},
	})

	if err != nil {
		log.Fatal("Wails 启动失败:", err.Error())
	}
}
