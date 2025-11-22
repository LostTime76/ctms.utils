from pathlib import Path

def str2path(path: str | Path) -> Path:
	"""
	Converts the input string into a path object

	Args:
		path: The input string to convert into a path object

	Returns:
		If the input path is a string, the converted path object is returned, otherwise, no
		conversion is performed and the input path argument is returned as is.
	"""
	return Path(path) if isinstance(path, str) else path

def path2str(path: str | Path) -> str:
	"""
	Resolves a path object into a string representing an absolute path

	Args:
		path: The path object to resolve into a string

	Returns:
		If the input path is a path object, it is resolved into a string, otherwise, no resolution
		is performed and the input path argument is returned as is.
	"""
	return str(path.resolve()) if isinstance(path, Path) else path