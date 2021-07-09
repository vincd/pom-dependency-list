import os
import re
from bs4 import BeautifulSoup

RE_PROPERTY = re.compile(r'(\${.*?})')


def find_pom_files(path):
	pom_files = []
	for root, dirs, files in os.walk(path):
		for filename in files:
			if filename == "pom.xml":
				pom_files.append(os.path.join(root, filename))

	return pom_files

def get_node_text(node, tag):
	n = node.find(tag.lower(), recursive=False)
	return n.get_text() if n else ''

def make_maven_identifier(groupId, artifactId, version):
	if version and len(version) > 0:
		return f'maven:{groupId.lower()}:{artifactId.lower()}@{version.lower()}'
	else:
		return f'maven:{groupId.lower()}:{artifactId.lower()}'

def make_snyk_url(id):
	return f"https://snyk.io/vuln/{id}"

def make_maven_url(id):
	return f"https://mvnrepository.com/artifact/{id.replace(':', '/', 2).replace('@', '/')}"


class PomAnalyzer():
	def __init__(self, path):
		self.__path = path
		self.__parent = None
		self.__children = []
		self.__dependencies = []
		self.analyze_file()

	def analyze_file(self):
		self.__pom = {}

		with open(self.__path) as fd:
			soup = BeautifulSoup(fd.read(), 'html.parser')

		project = soup.find('project', recursive=False)
		parent = soup.find('parent')
		properties = project.find('properties', recursive=False)
		dependencies = project.find('dependencies', recursive=False)
		dependency_management = project.find('dependencymanagement', recursive=False)

		self.__pom['groupId'] = get_node_text(project, 'groupId')
		self.__pom['artifactId'] = get_node_text(project, 'artifactId')
		self.__pom['version'] = get_node_text(project, 'version')
		self.__pom['packaging'] = get_node_text(project, 'packaging')
		self.__pom['properties'] = {}
		self.__pom['dependencies'] = []
		self.__pom['dependencies_management'] = []

		if parent:
			self.__pom['parent'] = {}
			self.__pom['parent']['groupId'] = get_node_text(parent, 'groupId')
			self.__pom['parent']['artifactId'] = get_node_text(parent, 'artifactId')
			self.__pom['parent']['version'] = get_node_text(parent, 'version')

		if properties:
			for prop in properties.children:
				if prop.name and prop.string:
					prop_name = prop.name.lower()
					self.__pom['properties'][prop_name] = prop.string

		if dependencies:
			for dependency in dependencies.find_all('dependency', recursive=False):
				dep = {}
				dep['groupId'] =  get_node_text(dependency, 'groupId')
				dep['artifactId'] = get_node_text(dependency, 'artifactId')
				dep['version'] = get_node_text(dependency, 'version')
				dep['scope'] = get_node_text(dependency, 'scope')
				dep['type'] = get_node_text(dependency, 'type')
				self.__pom['dependencies'].append(dep)

		if dependency_management:
			dependencies_management = dependency_management.find_all('dependencies', recursive=False)
			for dependencies in dependencies_management:
				for dependency in dependencies.find_all('dependency', recursive=False):
					dep = {}
					dep['groupId'] =  get_node_text(dependency, 'groupId')
					dep['artifactId'] = get_node_text(dependency, 'artifactId')
					dep['version'] = get_node_text(dependency, 'version')
					dep['scope'] = get_node_text(dependency, 'scope')
					dep['type'] = get_node_text(dependency, 'type')
					self.__pom['dependencies_management'].append(dep)


	def set_parent(self, pom):
		self.__parent = pom

	def add_child(self, pom):
		self.__children.append(pom)

	def get_parent(self):
		return self.__parent

	def get_identifier(self):
		return make_maven_identifier(self.__pom['groupId'], self.__pom['artifactId'], self.__pom['version'] if 'version' in self.__pom else '')

	def get_parent_identifier(self):
		if 'parent' in self.__pom:
			return make_maven_identifier(self.__pom['parent']['groupId'], self.__pom['parent']['artifactId'], self.__pom['parent']['version'] if 'version' in self.__pom['parent'] else '')
		else:
			return ''

	def get_dependencies(self):
		return self.__dependencies

	def resolve_dependencies(self, poms):
		parent_id = self.get_parent_identifier()

		if parent_id:
			found = False

			for p in poms:
				if p.get_identifier() == parent_id:
					found = True
					pom.set_parent(p)
					p.add_child(pom)
					if self.__pom['groupId'] == '':
						self.__pom['groupId'] = self.__parent.__pom['groupId']
					if self.__pom['version'] == '':
						self.__pom['version'] = self.__parent.__pom['version']
					break
			else:
				print(f'[!] "{self.get_identifier()}" cannot find parent in pom files with id "{parent_id}"')

		for dep in self.__pom['dependencies'] + self.__pom['dependencies_management']:
			groupId = self.resolve_property(dep['groupId'])
			artifactId = self.resolve_property(dep['artifactId'])
			version = self.resolve_property(dep['version'])
			scope = self.resolve_property(dep['scope'])
			dep_type = self.resolve_property(dep['type'])

			identifier = make_maven_identifier(groupId, artifactId, version)
			self.__dependencies.append({
				'identifier': identifier,
				'scope': scope,
				'type': dep_type,
				'snyk_url': make_snyk_url(identifier),
				'maven_url': make_maven_url(identifier)
			})

	def resolve_property(self, property_value):
		for match in RE_PROPERTY.finditer(property_value):
			prop = match.group()
			prop_name = prop[2:-1].lower()
			prop_value = ''

			if prop_name[:8] == 'project.':
				project_prop_name = prop_name[8:].lower()

				for k, v in self.__pom.items():
					if k.lower() == project_prop_name:
						prop_value = self.__pom[k]
						break
				else:
					raise Exception(f'Cannot find property "{project_prop_name}" in current project properties.')
			else:
				if prop_name in self.__pom['properties']:
					prop_value = self.__pom['properties'][prop_name]
				elif self.__parent:
					prop_value = self.__parent.resolve_property(property_value)
				else:
					raise Exception(f'Cannot find property "{prop}".')

			property_value = property_value.replace(prop, prop_value)

		return property_value


if __name__ == '__main__':
	import sys
	import json

	if len(sys.argv) != 2:
		print(f'Usage: {sys.argv[0]} path')
		exit()

	root_path = sys.argv[1]
	pom_files = find_pom_files(root_path)
	poms = []

	for pom_path in pom_files:
		poms.append(PomAnalyzer(pom_path))

	dependencies = []
	for pom in poms:
		pom.resolve_dependencies(poms)
		dependencies.append({
			pom.get_identifier(): pom.get_dependencies()
		})

	print(json.dumps(dependencies, indent=4, sort_keys=False))
