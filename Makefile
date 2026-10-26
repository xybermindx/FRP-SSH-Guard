.PHONY: all lint test privacy deb dist release bump-revision clean
all: release

lint:
	@for f in bin/*.sh install.sh uninstall.sh; do bash -n "$$f" || exit 1; done
	@for f in packaging/run packaging/preinst packaging/postinst packaging/prerm packaging/postrm scripts/hooks/*; do sh -n "$$f" || exit 1; done
	@python3 -c "import ast,pathlib; [ast.parse(p.read_text(), filename=str(p)) for d in ('bin','scripts','tests') for p in pathlib.Path(d).glob('*.py')]"
	@echo "Syntax checks passed"

privacy:
	python3 scripts/privacy.py --source

test: lint privacy
	python3 -m unittest discover -s tests -v

deb:
	python3 scripts/build.py deb

dist:
	python3 scripts/build.py source

release: test
	python3 scripts/build.py release

bump-revision:
	python3 scripts/build.py bump-revision

clean:
	rm -rf build dist
