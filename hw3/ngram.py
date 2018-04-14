import argparse
from collections import Counter
from time import time
import codecs


if __name__ == '__main__':
	# parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("n", type=int, help="length of the ngrams")
	parser.add_argument("s", type=int, help="length of the slide")
	parser.add_argument("input", help="name of the file to analyze")
	parser.add_argument("output", help="name of the output file")
	args = parser.parse_args()

	n, s = args.n, args.s
	input_file, output_file = args.input, args.output

	# start to count time
	start = time()
	# use a Counter data structure (a HashMap) to store grams and frequency
	c = Counter()
	# every time read n bytes into memory then seek back n-s bytes
	with open(input_file, 'rb') as f:
		byte = f.read(n)
		while byte != b"":
			if codecs.encode(byte, 'hex') in c:
				c[codecs.encode(byte, 'hex')] += 1
			else:
				c[codecs.encode(byte, 'hex')] = 0
			f.seek(n - s, 1)
			byte = f.read(n)
	# get 30 most common grams then sort out most common 20
	common = c.most_common(30)
	print(common)
	# get 20th gram then compare and get others that have the same frequency
	candidates = []
	for i in range(len(common)):
		if common[i][1] == common[19][1]:
			candidates.append(common[i])
	# sort these grams, set the smallest ones into original list
	candidates = sorted(candidates)
	print(candidates)
	j = 0
	for i in range(20):
		if common[i][1] == common[19][1]:
			common[i] = candidates[j]
			j += 1
	print(common[:20])

	# end to count time
	end = time()
	print(end - start)

	with open(output_file, 'w') as f:
		f.write("20 most common grams and frequency:\n")
		for i in range(20):
			f.write(common[i][0].decode("utf-8") + ' ' + str(common[i][1]) + '\n')



