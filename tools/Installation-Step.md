Install phpjoern:
Follow instruction written by authors.
	1. PHPJoern is compatible with PHP 7.2. Use php -m to check if
	ast module is loaded, or check in shared folder created after 
	the command `sudo make install` if ast.so exists.
	2. Install gradle to build Joern. The Joern version working 
	with PHPJoern is compatible with gradle 3.5.1 and openjdk-8-
	(LeftShift() 
	function is deprecated from gradle version 4.x onward).
	3.  Install pygraphviz:
	`sudo apt-get install -y graphviz-dev`
	`pip3 install pygraphviz`
	4. Follow the rest of author's instruction to build joern.
	
## Fix error: comand 'x86_64-linux-gnu-gcc' failed with exit status 1
	`sudo apt-get install python3 python-dev python3-dev \
     build-essential libssl-dev libffi-dev \
     libxml2-dev libxslt1-dev zlib1g-dev \
     python-pip`
     
     `apt-get install -y graphviz-dev`
