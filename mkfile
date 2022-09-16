SHELL=/bin/rc

TARG=\
	./secstore \
	./internal/cbc \
	./internal/pak \
	./internal/sio \
	./internal/ssl \
	./cmd/secfiles \

all:V:
	for a in $TARG; do go build $a; done
	go vet $TARG

fmt:V:
	for a in $TARG; do gofmt -s -l -w $a/*.go; done

test:V:
	go test ./internal/pak
	go test ./internal/ssl
	go test -v ./secstore
