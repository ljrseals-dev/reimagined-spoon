.PHONY: index suite demo critic clean

index:
	python corpus/build_index.py manuscript.md corpus/index.json

suite:
	python src/run_suite.py

demo:
	python src/critic.py "We changed the expected outcomes to match what the system now says."

critic:
	python src/critic.py --file $(FILE) --provider $(PROVIDER)

clean:
	rm -f logs/runs.jsonl
