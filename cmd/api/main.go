package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sn-go-api/internal/config"
	"sn-go-api/internal/server"
)

func main() {
	if err := config.LoadDotEnv(".env"); err != nil {
		log.Printf("dotenv warning: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	handler, err := server.NewRouter(cfg)
	if err != nil {
		log.Fatalf("router error: %v", err)
	}

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout,
		IdleTimeout:  cfg.HTTPIdleTimeout,
	}

	go func() {
		log.Printf("[%s] listening on %s", cfg.AppName, httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen error: %v", err)
		}
	}()

	waitForShutdown(httpServer, cfg.HTTPShutdownTimeout)
}

func waitForShutdown(httpServer *http.Server, timeout time.Duration) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	sig := <-stop
	log.Printf("signal received: %s", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
		return
	}

	log.Println("server stopped")
}
