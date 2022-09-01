SHELL=/bin/rc

TARG=\
	./secstore \
	./internal/ssl \

all:V:
	for a in $TARG; do go build $a; done
	go vet $TARG

fmt:V:
	for a in $TARG; do gofmt -s -l -w $a/*.go; done

test:V:
	go test -v ./secstore
	go test ./internal/ssl
