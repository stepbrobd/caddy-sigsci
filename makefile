.PHONY: build run agent

build:
	xcaddy build --with github.com/stepbrobd/caddy-sigsci=.

run:
	./caddy run --config ./caddyfile

agent:
	go run ./cmd/fakeagent
