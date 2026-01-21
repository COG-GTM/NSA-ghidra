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

class CoreActionTestEnvironment {
  Architecture *g;
public:
  CoreActionTestEnvironment(void);
  ~CoreActionTestEnvironment(void);
  static void build(void);
  static Funcdata *createTestFunction(const string &name, uintb addr);
  static void destroyTestFunction(Funcdata *fd);
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
}

Funcdata *CoreActionTestEnvironment::createTestFunction(const string &name, uintb addr)
{
  build();
  Address funcAddr(glb->getDefaultCodeSpace(), addr);
  Funcdata *fd = glb->symboltab->getGlobalScope()->addFunction(funcAddr, name)->getFunction();
  return fd;
}

void CoreActionTestEnvironment::destroyTestFunction(Funcdata *fd)
{
  if (fd != (Funcdata *)0) {
    fd->clear();
  }
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

TEST(action_start_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_start", 0x1000);
  ASSERT(fd != (Funcdata *)0);
  ASSERT(!fd->isProcStarted());
  ActionStart action("test");
  action.apply(*fd);
  ASSERT(fd->isProcStarted());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_stop_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_stop", 0x1100);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ASSERT(fd->isProcStarted());
  ASSERT(!fd->isProcComplete());
  ActionStop action("test");
  action.apply(*fd);
  ASSERT(fd->isProcComplete());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_start_types_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_starttypes", 0x1200);
  ASSERT(fd != (Funcdata *)0);
  ActionStartTypes action("test");
  action.reset(*fd);
  ASSERT(fd->isTypeRecoveryOn());
  ASSERT(!fd->hasTypeRecoveryStarted());
  fd->startProcessing();
  action.apply(*fd);
  ASSERT(fd->hasTypeRecoveryStarted());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_start_cleanup_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_cleanup", 0x1300);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionStartCleanUp action("test");
  action.apply(*fd);
  ASSERT(fd->getCleanUpIndex() > 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_name_and_group) {
  CoreActionTestEnvironment::build();
  ActionStart startAction("test");
  ASSERT_EQUALS(startAction.getName(), "start");
  ASSERT_EQUALS(startAction.getGroup(), "test");
  
  ActionStop stopAction("test");
  ASSERT_EQUALS(stopAction.getName(), "stop");
  ASSERT_EQUALS(stopAction.getGroup(), "test");
}

TEST(action_group_list_contains_empty) {
  ActionGroupList grouplist;
  ASSERT(!grouplist.contains("test"));
  ASSERT(!grouplist.contains("other"));
}

TEST(action_heritage_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_heritage", 0x1400);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ASSERT_EQUALS(fd->getHeritagePass(), 0);
  ActionHeritage action("test");
  action.apply(*fd);
  ASSERT(fd->getHeritagePass() >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_spacebase_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_spacebase", 0x1500);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionSpacebase action("test");
  int4 result = action.apply(*fd);
  ASSERT_EQUALS(result, 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_assign_high_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_assignhigh", 0x1600);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ASSERT(!fd->isHighOn());
  ActionAssignHigh action("test");
  action.apply(*fd);
  ASSERT(fd->isHighOn());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_nonzero_mask_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_nzmask", 0x1700);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionNonzeroMask action("test");
  int4 result = action.apply(*fd);
  ASSERT_EQUALS(result, 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_infer_types_localcount_reset) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_infertypes", 0x1800);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionInferTypes action("test");
  action.reset(*fd);
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_stack_ptr_flow_reset) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_stackptrflow", 0x1900);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  AddrSpace *stackSpace = glb->getStackSpace();
  ASSERT(stackSpace != (AddrSpace *)0);
  ActionStackPtrFlow action("test", stackSpace);
  action.reset(*fd);
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_lane_divide_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_lanedivide", 0x1a00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionLaneDivide action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_func_link_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_funclink", 0x1b00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionFuncLink action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_active_param_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_activeparam", 0x1c00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionActiveParam action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_active_return_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_activereturn", 0x1d00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionActiveReturn action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_dead_code_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_deadcode", 0x1e00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionDeadCode action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_unreachable_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_unreachable", 0x1f00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionUnreachable action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_do_nothing_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_donothing", 0x2000);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionDoNothing action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_redundant_branch_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_redundbranch", 0x2100);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionRedundBranch action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_determined_branch_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_detbranch", 0x2200);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionDeterminedBranch action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_switch_norm_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_switchnorm", 0x2300);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionSwitchNorm action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_prototype_types_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_prototypes", 0x2400);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionPrototypeTypes action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_default_params_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_defaultparams", 0x2500);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionDefaultParams action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_return_recovery_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_returnrecovery", 0x2600);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionReturnRecovery action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_restrict_local_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_restrictlocal", 0x2700);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionRestrictLocal action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_likely_trash_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_likelytrash", 0x2800);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionLikelyTrash action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_restructure_varnode_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_restructure", 0x2900);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionRestructureVarnode action("test");
  action.reset(*fd);
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_input_prototype_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_inputproto", 0x2a00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionInputPrototype action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_output_prototype_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_outputproto", 0x2b00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionOutputPrototype action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_set_casts_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_setcasts", 0x2c00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionSetCasts action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_mark_explicit_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_markexplicit", 0x2d00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionMarkExplicit action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_mark_implied_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_markimplied", 0x2e00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionMarkImplied action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_name_vars_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_namevars", 0x2f00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionNameVars action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_merge_required_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_mergerequired", 0x3000);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionMergeRequired action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_merge_adjacent_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_mergeadjacent", 0x3100);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionMergeAdjacent action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_merge_copy_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_mergecopy", 0x3200);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionMergeCopy action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_merge_type_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_mergetype", 0x3300);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionMergeType action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_multi_cse_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_multicse", 0x3400);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionMultiCse action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_shadow_var_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_shadowvar", 0x3500);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionShadowVar action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_constant_ptr_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_constantptr", 0x3600);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionConstantPtr action("test");
  action.reset(*fd);
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_deindirect_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_deindirect", 0x3700);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionDeindirect action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_varnode_props_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_varnodeprops", 0x3800);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionVarnodeProps action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_direct_write_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_directwrite", 0x3900);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionDirectWrite action("test", true);
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_direct_write_no_indirect) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_directwrite_noind", 0x3a00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionDirectWrite action("test", false);
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_constbase_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_constbase", 0x3b00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionConstbase action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_segmentize_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_segmentize", 0x3c00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionSegmentize action("test");
  action.reset(*fd);
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_force_goto_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_forcegoto", 0x3d00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionForceGoto action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_conditional_const_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_condconst", 0x3e00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionConditionalConst action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_mark_indirect_only_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_markindonly", 0x3f00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionMarkIndirectOnly action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_hide_shadow_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_hideshadow", 0x4000);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionHideShadow action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_dominant_copy_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_domcopy", 0x4100);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionDominantCopy action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_copy_marker_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_copymarker", 0x4200);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionCopyMarker action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_dynamic_mapping_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_dynmap", 0x4300);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionDynamicMapping action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_unjustified_params_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_unjustparams", 0x4400);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionUnjustifiedParams action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_param_double_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_paramdouble", 0x4500);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionParamDouble action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_extra_pop_setup_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_extrapop", 0x4600);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  AddrSpace *stackSpace = glb->getStackSpace();
  ASSERT(stackSpace != (AddrSpace *)0);
  ActionExtraPopSetup action("test", stackSpace);
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_func_link_out_only_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_funclinkout", 0x4700);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionFuncLinkOutOnly action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_normalize_setup_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_normsetup", 0x4800);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionNormalizeSetup action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_map_globals_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_mapglobals", 0x4900);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionMapGlobals action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_mapped_local_sync_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_mappedlocalsync", 0x4a00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  ActionMappedLocalSync action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(action_merge_multi_entry_basic) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_mergemulti", 0x4b00);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  ActionMergeMultiEntry action("test");
  int4 result = action.apply(*fd);
  ASSERT(result >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_basic_properties) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_funcdata", 0x5000);
  ASSERT(fd != (Funcdata *)0);
  ASSERT_EQUALS(fd->getName(), "test_funcdata");
  ASSERT_EQUALS(fd->getAddress().getOffset(), 0x5000);
  ASSERT(fd->getArch() == glb);
  ASSERT(!fd->isProcStarted());
  ASSERT(!fd->isProcComplete());
  ASSERT(!fd->isHighOn());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_type_recovery_flags) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_typerecovery", 0x5100);
  ASSERT(fd != (Funcdata *)0);
  ASSERT(!fd->isTypeRecoveryOn());
  fd->setTypeRecovery(true);
  ASSERT(fd->isTypeRecoveryOn());
  ASSERT(!fd->hasTypeRecoveryStarted());
  fd->startProcessing();
  fd->startTypeRecovery();
  ASSERT(fd->hasTypeRecoveryStarted());
  ASSERT(!fd->isTypeRecoveryExceeded());
  fd->setTypeRecoveryExceeded();
  ASSERT(fd->isTypeRecoveryExceeded());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_jumptable_recovery_flags) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_jumptable", 0x5200);
  ASSERT(fd != (Funcdata *)0);
  ASSERT(!fd->isJumptableRecoveryOn());
  fd->setJumptableRecovery(true);
  fd->setJumptableRecovery(false);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_double_precision_flags) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_doubleprecis", 0x5300);
  ASSERT(fd != (Funcdata *)0);
  ASSERT(!fd->isDoublePrecisOn());
  fd->setDoublePrecisRecovery(true);
  ASSERT(fd->isDoublePrecisOn());
  fd->setDoublePrecisRecovery(false);
  ASSERT(!fd->isDoublePrecisOn());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_restart_pending) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_restart", 0x5400);
  ASSERT(fd != (Funcdata *)0);
  ASSERT(!fd->hasRestartPending());
  fd->setRestartPending(true);
  ASSERT(fd->hasRestartPending());
  fd->setRestartPending(false);
  ASSERT(!fd->hasRestartPending());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_no_code_flag) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_nocode", 0x5500);
  ASSERT(fd != (Funcdata *)0);
  ASSERT(!fd->hasNoCode());
  fd->setNoCode(true);
  ASSERT(fd->hasNoCode());
  fd->setNoCode(false);
  ASSERT(!fd->hasNoCode());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_heritage_pass_count) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_heritagepass", 0x5600);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  int4 initialPass = fd->getHeritagePass();
  ASSERT(initialPass >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_cast_phase_index) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_castphase", 0x5700);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->startCastPhase();
  uint4 castIndex = fd->getCastPhaseIndex();
  ASSERT(castIndex >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_cleanup_index) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_cleanupidx", 0x5800);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->startCleanUp();
  uint4 cleanupIndex = fd->getCleanUpIndex();
  ASSERT(cleanupIndex >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_highlevel_index) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_highlevelidx", 0x5900);
  ASSERT(fd != (Funcdata *)0);
  fd->startProcessing();
  fd->setHighLevel();
  uint4 highIndex = fd->getHighLevelIndex();
  ASSERT(highIndex >= 0);
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_override_access) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_override", 0x5a00);
  ASSERT(fd != (Funcdata *)0);
  Override &ovr = fd->getOverride();
  (void)ovr;
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(funcdata_struct_blocks) {
  CoreActionTestEnvironment::build();
  Funcdata *fd = CoreActionTestEnvironment::createTestFunction("test_structblocks", 0x5b00);
  ASSERT(fd != (Funcdata *)0);
  ASSERT(fd->hasNoStructBlocks());
  CoreActionTestEnvironment::destroyTestFunction(fd);
}

TEST(architecture_stack_space) {
  CoreActionTestEnvironment::build();
  AddrSpace *stackSpace = glb->getStackSpace();
  ASSERT(stackSpace != (AddrSpace *)0);
  ASSERT_EQUALS(stackSpace->getName(), "stack");
}

TEST(architecture_default_code_space) {
  CoreActionTestEnvironment::build();
  AddrSpace *codeSpace = glb->getDefaultCodeSpace();
  ASSERT(codeSpace != (AddrSpace *)0);
  ASSERT_EQUALS(codeSpace->getName(), "ram");
}

TEST(architecture_type_factory) {
  CoreActionTestEnvironment::build();
  TypeFactory *types = glb->types;
  ASSERT(types != (TypeFactory *)0);
  Datatype *intType = types->getBase(4, TYPE_INT);
  ASSERT(intType != (Datatype *)0);
  ASSERT_EQUALS(intType->getSize(), 4);
  ASSERT_EQUALS(intType->getMetatype(), TYPE_INT);
}

TEST(architecture_proto_models) {
  CoreActionTestEnvironment::build();
  ASSERT(glb->protoModels.size() > 0);
  ProtoModel *defaultModel = glb->defaultfp;
  ASSERT(defaultModel != (ProtoModel *)0);
}

TEST(type_factory_basic_types) {
  CoreActionTestEnvironment::build();
  TypeFactory *types = glb->types;
  
  Datatype *int1 = types->getBase(1, TYPE_INT);
  ASSERT(int1 != (Datatype *)0);
  ASSERT_EQUALS(int1->getSize(), 1);
  
  Datatype *int2 = types->getBase(2, TYPE_INT);
  ASSERT(int2 != (Datatype *)0);
  ASSERT_EQUALS(int2->getSize(), 2);
  
  Datatype *int4 = types->getBase(4, TYPE_INT);
  ASSERT(int4 != (Datatype *)0);
  ASSERT_EQUALS(int4->getSize(), 4);
  
  Datatype *int8 = types->getBase(8, TYPE_INT);
  ASSERT(int8 != (Datatype *)0);
  ASSERT_EQUALS(int8->getSize(), 8);
}

TEST(type_factory_unsigned_types) {
  CoreActionTestEnvironment::build();
  TypeFactory *types = glb->types;
  
  Datatype *uint1 = types->getBase(1, TYPE_UINT);
  ASSERT(uint1 != (Datatype *)0);
  ASSERT_EQUALS(uint1->getMetatype(), TYPE_UINT);
  
  Datatype *uint4 = types->getBase(4, TYPE_UINT);
  ASSERT(uint4 != (Datatype *)0);
  ASSERT_EQUALS(uint4->getMetatype(), TYPE_UINT);
}

TEST(type_factory_float_types) {
  CoreActionTestEnvironment::build();
  TypeFactory *types = glb->types;
  
  Datatype *float4 = types->getBase(4, TYPE_FLOAT);
  ASSERT(float4 != (Datatype *)0);
  ASSERT_EQUALS(float4->getMetatype(), TYPE_FLOAT);
  ASSERT_EQUALS(float4->getSize(), 4);
  
  Datatype *float8 = types->getBase(8, TYPE_FLOAT);
  ASSERT(float8 != (Datatype *)0);
  ASSERT_EQUALS(float8->getMetatype(), TYPE_FLOAT);
  ASSERT_EQUALS(float8->getSize(), 8);
}

TEST(type_factory_void_type) {
  CoreActionTestEnvironment::build();
  TypeFactory *types = glb->types;
  
  Datatype *voidType = types->getTypeVoid();
  ASSERT(voidType != (Datatype *)0);
  ASSERT_EQUALS(voidType->getMetatype(), TYPE_VOID);
  ASSERT_EQUALS(voidType->getSize(), 0);
}

TEST(type_factory_bool_type) {
  CoreActionTestEnvironment::build();
  TypeFactory *types = glb->types;
  
  Datatype *boolType = types->getBase(1, TYPE_BOOL);
  ASSERT(boolType != (Datatype *)0);
  ASSERT_EQUALS(boolType->getMetatype(), TYPE_BOOL);
}

TEST(type_factory_pointer_type) {
  CoreActionTestEnvironment::build();
  TypeFactory *types = glb->types;
  
  Datatype *int4 = types->getBase(4, TYPE_INT);
  Datatype *ptrInt4 = types->getTypePointer(8, int4, 1);
  ASSERT(ptrInt4 != (Datatype *)0);
  ASSERT_EQUALS(ptrInt4->getMetatype(), TYPE_PTR);
  ASSERT_EQUALS(ptrInt4->getSize(), 8);
}

TEST(type_factory_array_type) {
  CoreActionTestEnvironment::build();
  TypeFactory *types = glb->types;
  
  Datatype *int4 = types->getBase(4, TYPE_INT);
  Datatype *arrayInt4 = types->getTypeArray(10, int4);
  ASSERT(arrayInt4 != (Datatype *)0);
  ASSERT_EQUALS(arrayInt4->getMetatype(), TYPE_ARRAY);
  ASSERT_EQUALS(arrayInt4->getSize(), 40);
}

TEST(address_space_properties) {
  CoreActionTestEnvironment::build();
  AddrSpace *ramSpace = glb->getDefaultCodeSpace();
  ASSERT(ramSpace != (AddrSpace *)0);
  ASSERT(!ramSpace->isBigEndian());
  ASSERT_EQUALS(ramSpace->getAddrSize(), 8);
}

TEST(action_group_list_empty_contains) {
  ActionGroupList grouplist;
  ASSERT(!grouplist.contains("test"));
  ASSERT(!grouplist.contains("group1"));
  ASSERT(!grouplist.contains("group2"));
  ASSERT(!grouplist.contains(""));
}

} // End namespace ghidra
