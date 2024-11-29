project('libwas', ['c', 'cpp'], version: '1.31',
  meson_version: '>= 0.56',
  default_options: [
    'c_std=c11',
    'cpp_std=c++17',
    'warning_level=3',
  ],
)

debug = get_option('b_ndebug') != 'true'

splitted_version = meson.project_version().split('.')

compiler = meson.get_compiler('cpp')
c_compiler = meson.get_compiler('c')

pkg_mod = import('pkgconfig')

apreq2_config = find_program('apreq2-config', required: get_option('apreq2'))

if apreq2_config.found()
  apreq2_includedir = run_command(apreq2_config, '--includedir', check: true)
  if apreq2_includedir.returncode() != 0
    error('"apreq2-config --includedir" failed')
  endif

  apreq2_linkld = run_command(apreq2_config, '--link-ld', check: true)
  if apreq2_linkld.returncode() != 0
    error('"apreq2-config --link-ld" failed')
  endif

  libapr = dependency('apr-1', include_type: 'system')
  libapr_util = dependency('apr-util-1', include_type: 'system')

  libapreq2 = declare_dependency(
    include_directories: include_directories(apreq2_includedir.stdout().strip(), is_system: true),
    link_args: apreq2_linkld.stdout().strip().split(),
    dependencies: [ libapr, libapr_util ],
  )
else
  libapreq2 = disabler()
endif

common_flags = [
  '-D_REENTRANT', '-D_GNU_SOURCE',
]

test_common_flags = [
  '-Wcast-align',
  '-Wcast-qual',
  '-Wdouble-promotion',
  '-Wfloat-equal',
  '-Wmissing-declarations',
  '-Wmissing-format-attribute',
  '-Wmissing-noreturn',
  '-Wredundant-decls',
  '-Wshadow',
  '-Wundef',
  '-Wunused',
  '-Wvla',
  '-Wwrite-strings',

  # clang specific warning options:
  '-Wunreachable-code-aggressive',
  '-Wused-but-marked-unused',
]

if not debug and not meson.is_subproject()
  test_common_flags += [
    '-ffunction-sections',
    '-fdata-sections',
  ]

  add_global_link_arguments(
    compiler.get_supported_link_arguments(
      '-Wl,--gc-sections',
      '-Wl,--icf=all',
    ),
    language: 'cpp'
  )

  add_global_link_arguments(
    c_compiler.get_supported_link_arguments(
      '-Wl,--gc-sections',
      '-Wl,--icf=all',
    ),
    language: 'c'
  )
endif

test_cxxflags = test_common_flags + [
  '-fno-exceptions', '-fno-rtti',

  '-fno-threadsafe-statics',
  '-fmerge-all-constants',

  '-Wcomma-subscript',
  '-Wextra-semi',
  '-Wmismatched-tags',
  '-Woverloaded-virtual',
  '-Wsign-promo',
  '-Wvolatile',
  '-Wvirtual-inheritance',

  '-Wno-missing-field-initializers',

  # clang specific warning options:
  '-Wcomma',
  '-Wheader-hygiene',
  '-Winconsistent-missing-destructor-override',
]

test_cflags = test_common_flags + [
  '-Wmissing-prototypes', '-Wstrict-prototypes',
  '-Wbad-function-cast',
  '-Waggregate-return',
  '-Wnested-externs',
]

add_project_arguments(common_flags, language: 'c')
add_project_arguments(common_flags, language: 'cpp')

add_project_arguments(compiler.get_supported_arguments(test_cxxflags), language: 'cpp')
add_project_arguments(c_compiler.get_supported_arguments(test_cflags), language: 'c')

libhttp = dependency('libcm4all-http', version: '>= 1.2.6')
libcore = dependency('libcore', version: '>= 1.20.5', required: get_option('xios'), disabler: true)

inc = include_directories('src', 'include')

pkg_mod.generate(
  version: meson.project_version(),
  name: 'libcm4all-was-protocol',
  description: 'CM4all WAS protocol library',
  install_dir: join_paths(get_option('datadir'), 'pkgconfig')
)

libwas_protocol_dep = declare_dependency(
  include_directories: inc,
)

libwas_simple = library('cm4all-was-simple',
  'src/iterator.cxx',
  'src/simple.cxx',
  'src/multi.cxx',
  link_depends: [
    'libcm4all-was-simple.ld'
  ],
  include_directories: inc,
  dependencies: [
    libhttp,
  ],
  link_args: [
    '-Wl,--version-script=' + join_paths(meson.project_source_root(), 'libcm4all-was-simple.ld'),
  ],
  version: meson.project_version(),
  soversion: splitted_version[0],
  install: true,
)
libwas_simple_dep = declare_dependency(
  link_with: libwas_simple,
  include_directories: inc,
  dependencies: [
    libhttp,
  ],
)

if libhttp.type_name() != 'internal'
  pkg_mod.generate(
    libwas_simple,
    version: meson.project_version(),
    name: 'libcm4all-was-simple',
    description: 'CM4all simple WAS server library',
    requires: [libhttp],
  )
endif

libwas_apreq = library('cm4all-was-apreq',
  'src/parser.c',
  'src/bucket.c',
  link_depends: [
    'libcm4all-was-apreq.ld'
  ],
  include_directories: inc,
  dependencies: [
    libapreq2,
    libwas_simple_dep,
  ],
  c_args: [
    '-Wno-cast-qual',
  ],
  link_args: [
    '-Wl,--version-script=' + join_paths(meson.project_source_root(), 'libcm4all-was-apreq.ld'),
  ],
  version: meson.project_version(),
  soversion: splitted_version[0],
  install: true,
)
libwas_apreq_dep = declare_dependency(
  link_with: libwas_apreq,
  include_directories: inc,
)

if libhttp.type_name() != 'internal'
  pkg_mod.generate(
    libraries: libwas_apreq,
    version: meson.project_version(),
    name: 'libcm4all-was-apreq',
    description: 'CM4all WAS server library, request parser',
    requires: [libwas_simple],
  )
endif

libwas_xios = library('cm4all-was-xios',
  'src/istub.c',
  'src/ostub.c',
  link_depends: [
    'libcm4all-was-xios.ld'
  ],
  include_directories: inc,
  dependencies: [
    libcore,
    libwas_simple_dep,
  ],
  link_args: [
    '-Wl,--version-script=' + join_paths(meson.project_source_root(), 'libcm4all-was-xios.ld'),
  ],
  version: meson.project_version(),
  soversion: splitted_version[0],
  install: true,
)
libwas_xios_dep = declare_dependency(
  link_with: libwas_xios,
  include_directories: inc,
  dependencies: [
    libcore,
  ],
)

if libhttp.type_name() != 'internal'
  pkg_mod.generate(
    libraries: libwas_xios,
    version: meson.project_version(),
    name: 'libcm4all-was-xios',
    description: 'CM4all WAS server library, libcore xios implementation',
    requires: [libwas_simple, libcore],
  )
endif

install_headers(
  'include/was/apreq.h',
  'include/was/istub.h',
  'include/was/ostub.h',
  'include/was/protocol.h',
  'include/was/simple.h',
  'include/was/multi.h',
  'include/was/compiler.h',
  subdir: 'was')

subdir('test')
subdir('examples')
subdir('doc')
