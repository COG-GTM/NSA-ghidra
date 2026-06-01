/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "architecture.hh"
#include "grammar.hh"
#include "coreaction.hh"
#include "funcdata.hh"
#include "test.hh"
#include <iostream>

namespace ghidra {

static Architecture *glb = (Architecture *)0;
static TypeFactory *types = (TypeFactory *)0;

class CoreActionTestEnvironment {
  Architecture *g;
public:
  CoreActionTestEnvironment(void);
  ~CoreActionTestEnvironment(void);
  static void build(void);
};

static CoreActionTestEnvironment theEnviron;

CoreActionTestEnvironment::CoreActionTestEnvironment(void)
{
  g = (Architecture *)0;
}

void CoreActionTestEnvironment::build(void)
{
  if (theEnviron.g != (Architecture *)0) return;
  ArchitectureCapability *xmlCapability = ArchitectureCapability::getCapability("xml");
  istringstream s(
      "<binaryimage arch=\"x86:LE:64:default:gcc\"></binaryimage>"
  );
  DocumentStorage store;
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());

  theEnviron.g = xmlCapability->buildArchitecture("", "", &cout);
  theEnviron.g->init(store);

  glb = theEnviron.g;
  types = glb->types;
}

CoreActionTestEnvironment::~CoreActionTestEnvironment(void)
{
  if (g != (Architecture *)0)
    delete g;
}

Datatype *parseType(const string &text) {
  CoreActionTestEnvironment::build();
  istringstream s(text);
  string unused;
  return parse_type(s, unused, glb);
}

// Action Name and Group Tests

TEST(action_start_properties) {
  CoreActionTestEnvironment::build();
  ActionStart action("testgroup");
  ASSERT_EQUALS(action.getName(), "start");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

TEST(action_stop_properties) {
  CoreActionTestEnvironment::build();
  ActionStop action("testgroup");
  ASSERT_EQUALS(action.getName(), "stop");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

TEST(action_heritage_properties) {
  CoreActionTestEnvironment::build();
  ActionHeritage action("testgroup");
  ASSERT_EQUALS(action.getName(), "heritage");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

TEST(action_infer_types_properties) {
  CoreActionTestEnvironment::build();
  ActionInferTypes action("testgroup");
  ASSERT_EQUALS(action.getName(), "infertypes");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

TEST(action_stack_ptr_flow_properties) {
  CoreActionTestEnvironment::build();
  AddrSpace *stackSpace = glb->getStackSpace();
  ASSERT(stackSpace != (AddrSpace *)0);
  ActionStackPtrFlow action("testgroup", stackSpace);
  ASSERT_EQUALS(action.getName(), "stackptrflow");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

TEST(action_lane_divide_properties) {
  CoreActionTestEnvironment::build();
  ActionLaneDivide action("testgroup");
  ASSERT_EQUALS(action.getName(), "lanedivide");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

TEST(action_func_link_properties) {
  CoreActionTestEnvironment::build();
  ActionFuncLink action("testgroup");
  ASSERT_EQUALS(action.getName(), "funclink");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

TEST(action_active_param_properties) {
  CoreActionTestEnvironment::build();
  ActionActiveParam action("testgroup");
  ASSERT_EQUALS(action.getName(), "activeparam");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

TEST(action_active_return_properties) {
  CoreActionTestEnvironment::build();
  ActionActiveReturn action("testgroup");
  ASSERT_EQUALS(action.getName(), "activereturn");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

TEST(action_dead_code_properties) {
  CoreActionTestEnvironment::build();
  ActionDeadCode action("testgroup");
  ASSERT_EQUALS(action.getName(), "deadcode");
  ASSERT_EQUALS(action.getGroup(), "testgroup");
}

// ActionGroupList Tests

TEST(action_group_list_empty) {
  ActionGroupList grouplist;
  ASSERT(!grouplist.contains("test"));
  ASSERT(!grouplist.contains("other"));
}

// Architecture Tests

TEST(architecture_default_code_space) {
  CoreActionTestEnvironment::build();
  AddrSpace *codeSpace = glb->getDefaultCodeSpace();
  ASSERT(codeSpace != (AddrSpace *)0);
  ASSERT_EQUALS(codeSpace->getName(), "ram");
}

TEST(architecture_stack_space) {
  CoreActionTestEnvironment::build();
  AddrSpace *stackSpace = glb->getStackSpace();
  ASSERT(stackSpace != (AddrSpace *)0);
  ASSERT_EQUALS(stackSpace->getName(), "stack");
}

TEST(architecture_type_factory) {
  CoreActionTestEnvironment::build();
  ASSERT(glb->types != (TypeFactory *)0);
  ASSERT_EQUALS(glb->types, types);
}

// TypeFactory Tests

TEST(type_factory_basic_int_types) {
  CoreActionTestEnvironment::build();
  Datatype *int4 = types->getBase(4, TYPE_INT);
  ASSERT(int4 != (Datatype *)0);
  ASSERT_EQUALS(int4->getSize(), 4);
  ASSERT_EQUALS(int4->getMetatype(), TYPE_INT);
}

TEST(type_factory_basic_uint_types) {
  CoreActionTestEnvironment::build();
  Datatype *uint4 = types->getBase(4, TYPE_UINT);
  ASSERT(uint4 != (Datatype *)0);
  ASSERT_EQUALS(uint4->getSize(), 4);
  ASSERT_EQUALS(uint4->getMetatype(), TYPE_UINT);
}

TEST(type_factory_float_types) {
  CoreActionTestEnvironment::build();
  Datatype *float4 = types->getBase(4, TYPE_FLOAT);
  ASSERT(float4 != (Datatype *)0);
  ASSERT_EQUALS(float4->getSize(), 4);
  ASSERT_EQUALS(float4->getMetatype(), TYPE_FLOAT);
}

TEST(type_factory_void_type) {
  CoreActionTestEnvironment::build();
  Datatype *voidType = types->getTypeVoid();
  ASSERT(voidType != (Datatype *)0);
  ASSERT_EQUALS(voidType->getMetatype(), TYPE_VOID);
}

TEST(type_factory_pointer_type) {
  CoreActionTestEnvironment::build();
  Datatype *int4 = types->getBase(4, TYPE_INT);
  Datatype *ptrInt4 = types->getTypePointer(8, int4, 1);
  ASSERT(ptrInt4 != (Datatype *)0);
  ASSERT_EQUALS(ptrInt4->getSize(), 8);
  ASSERT_EQUALS(ptrInt4->getMetatype(), TYPE_PTR);
}

TEST(type_factory_array_type) {
  CoreActionTestEnvironment::build();
  Datatype *int4 = types->getBase(4, TYPE_INT);
  Datatype *arrayInt4 = types->getTypeArray(10, int4);
  ASSERT(arrayInt4 != (Datatype *)0);
  ASSERT_EQUALS(arrayInt4->getSize(), 40);
  ASSERT_EQUALS(arrayInt4->getMetatype(), TYPE_ARRAY);
}

// Type Parsing Tests

TEST(parse_type_int) {
  CoreActionTestEnvironment::build();
  Datatype *dt = parseType("int4");
  ASSERT(dt != (Datatype *)0);
  ASSERT_EQUALS(dt->getSize(), 4);
  ASSERT_EQUALS(dt->getMetatype(), TYPE_INT);
}

TEST(parse_type_pointer) {
  CoreActionTestEnvironment::build();
  Datatype *dt = parseType("int4 *");
  ASSERT(dt != (Datatype *)0);
  ASSERT_EQUALS(dt->getMetatype(), TYPE_PTR);
}

TEST(parse_type_struct) {
  CoreActionTestEnvironment::build();
  Datatype *dt = parseType("struct teststruct { int4 a; int4 b; }");
  ASSERT(dt != (Datatype *)0);
  ASSERT_EQUALS(dt->getMetatype(), TYPE_STRUCT);
  ASSERT_EQUALS(dt->getSize(), 8);
}

} // End namespace ghidra
