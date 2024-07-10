dev:
	go build -o gocert-clone cmd/main.go

release:
	go build -o gocert-clone -trimpath -buildvcs=false -ldflags "-w" cmd/main.go