project('libwas', ['c', 'cpp'], version: '1.17',
  default_options: [
    'c_std=c99',
    'cpp_std=c++14'
  ],
)

# TODO: use get_option('b_ndebug'), but that doesn't work with Meson 0.37.1
if get_option('buildtype') == 'debug'
  debug = true
else
  debug = false
endif

splitted_version = meson.project_version().split('.')

cc = meson.get_compiler('c')

pkg_mod = import('pkgconfig')

libapr = dependency('apr-1')
libapr_util = dependency('apr-util-1')

apreq2_config = find_program('apreq2-config')

apreq2_includedir = run_command(apreq2_config, '--includedir')
if apreq2_includedir.returncode() != 0
  error('"apreq2-config --includedir" failed')
endif

apreq2_linkld = run_command(apreq2_config, '--link-ld')
if apreq2_linkld.returncode() != 0
  error('"apreq2-config --link-ld" failed')
endif

libapreq2 = declare_dependency(compile_args: '-I' + apreq2_includedir.stdout().strip(),
                               link_args: apreq2_linkld.stdout().strip().split())

libhttp = dependency('libcm4all-http', version: '>= 1.2.6')
libcore = dependency('libcore', version: '>= 1.20.5')

common_flags = [
  '-D_REENTRANT', '-D_GNU_SOURCE',
  '-Wall',
  '-Wextra',
  '-Wwrite-strings', '-Wcast-qual', '-Wcast-align', '-Wfloat-equal',
  '-Wshadow', '-Wpointer-arith', '-Wsign-compare',
  '-Wmissing-declarations', '-Wmissing-noreturn', '-Wmissing-format-attribute',
  '-Wredundant-decls', '-Wno-long-long', '-Wundef',
  '-Wunused',
]

add_global_arguments(common_flags,
  '-Wmissing-prototypes', '-Wstrict-prototypes',
  '-Wbad-function-cast',
  '-Waggregate-return',
  '-Wredundant-decls', '-Wno-long-long', '-Wundef',
  '-Wnested-externs',
  '-pedantic',
  language: 'c')

add_global_arguments(common_flags,
  '-fno-exceptions', '-fno-rtti',
  '-fno-threadsafe-statics', '-fmerge-all-constants',
  '-Wno-missing-field-initializers',
  '-Wno-non-virtual-dtor',
  language: 'cpp')

inc = include_directories('src', 'include')

pkg_mod.generate(
  version: meson.project_version(),
  name: 'libcm4all-was-protocol',
  description: 'CM4all WAS protocol library',
  install_dir: join_paths(get_option('datadir'), 'pkgconfig')
)

libwas_simple = library('cm4all-was-simple',
  'src/iterator.cxx',
  'src/simple.cxx',
  link_depends: [
    'libcm4all-was-simple.ld'
  ],
  include_directories: inc,
  dependencies: [
    libhttp,
  ],
  link_args: [
    '-Wl,--version-script=' + join_paths(meson.source_root(), 'libcm4all-was-simple.ld'),
  ],
  version: meson.project_version(),
  soversion: splitted_version[0],
  install: true,
)
libwas_simple_dep = declare_dependency(link_with: libwas_simple)

pkg_mod.generate(
  libwas_simple,
  version: meson.project_version(),
  name: 'libcm4all-was-simple',
  description: 'CM4all simple WAS server library',
  requires: [libhttp],
)

libwas_apreq = library('cm4all-was-apreq',
  'src/parser.c',
  'src/bucket.c',
  link_depends: [
    'libcm4all-was-apreq.ld'
  ],
  include_directories: inc,
  dependencies: [
    libhttp,
    libapr, libapr_util, libapreq2,
    libwas_simple_dep,
  ],
  c_args: [
    '-Wno-cast-qual',
  ],
  link_args: [
    '-Wl,--version-script=' + join_paths(meson.source_root(), 'libcm4all-was-apreq.ld'),
  ],
  version: meson.project_version(),
  soversion: splitted_version[0],
  install: true,
)
libwas_apreq_dep = declare_dependency(link_with: libwas_apreq)

pkg_mod.generate(
  libraries: libwas_apreq,
  version: meson.project_version(),
  name: 'libcm4all-was-apreq',
  description: 'CM4all WAS server library, request parser',
  requires: [libwas_simple],
)

libwas_xios = library('cm4all-was-xios',
  'src/istub.c',
  'src/ostub.c',
  link_depends: [
    'libcm4all-was-xios.ld'
  ],
  include_directories: inc,
  dependencies: [
    libhttp,
    libcore,
    libwas_simple_dep,
  ],
  link_args: [
    '-Wl,--version-script=' + join_paths(meson.source_root(), 'libcm4all-was-xios.ld'),
  ],
  version: meson.project_version(),
  soversion: splitted_version[0],
  install: true,
)
libwas_xios_dep = declare_dependency(link_with: libwas_xios)

pkg_mod.generate(
  libraries: libwas_xios,
  version: meson.project_version(),
  name: 'libcm4all-was-xios',
  description: 'CM4all WAS server library, libcore xios implementation',
  requires: [libwas_simple, libcore],
)

install_headers(
  'include/was/apreq.h',
  'include/was/istub.h',
  'include/was/ostub.h',
  'include/was/protocol.h',
  'include/was/simple.h',
  'include/was/compiler.h',
  subdir: 'was')

subdir('test')
subdir('examples')
subdir('doc')
