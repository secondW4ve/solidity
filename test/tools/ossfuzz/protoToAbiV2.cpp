#include <regex>
#include <numeric>
#include <boost/range/adaptor/reversed.hpp>
#include <test/tools/ossfuzz/protoToAbiV2.h>
#include <libdevcore/StringUtils.h>
#include <libdevcore/Whiskers.h>
#include <liblangutil/Exceptions.h>

using namespace std;
using namespace dev;
using namespace dev::test::abiv2fuzzer;

StructType const* ProtoConverter::findStruct(Type const& _t)
{
	if (_t.has_nvtype() && _t.nvtype().has_stype())
		return &_t.nvtype().stype();
	else if (_t.has_nvtype() && _t.nvtype().has_arrtype())
		return findStruct(_t.nvtype().arrtype().t());
	else
		return nullptr;
}

string ProtoConverter::getQualifier(Type const& _type)
{
	if (m_isStateVar)
		return "";

	switch (_type.type_oneof_case())
	{
	case Type::kVtype:
		return "";
	case Type::kNvtype:
		return "memory";
	case Type::TYPE_ONEOF_NOT_SET:
		solAssert(false, "ABIv2 proto fuzzer: Invalid type");
	}
}

string ProtoConverter::appendVarDeclToOutput(
	string const& _type,
	string const& _varName,
	string const& _qualifier
)
{
	// One level of indentation for state variable declarations
	// Two levels of indentation for local variable declarations
	return Whiskers(R"(
	<?isLocalVar>	</isLocalVar><type><?qual> <qualifier></qual> <varName>;)"
		)
		("isLocalVar", !m_isStateVar)
		("type", _type)
		("qual", !_qualifier.empty())
		("qualifier", _qualifier)
		("varName", _varName)
		.render() +
		"\n";
}

bool ProtoConverter::isValueType(Type const& _type)
{
	switch (_type.type_oneof_case())
	{
	case Type::kVtype:
		return true;
	case Type::kNvtype:
		return false;
	case Type::TYPE_ONEOF_NOT_SET:
		solAssert(false, "ABIv2 proto fuzzer: Invalid type");
	}
}

pair<string, string> ProtoConverter::visit(Type const& _type)
{
	ostringstream local, global;

	auto varNames = newVarNames(getNextVarCounter());
	string varName = varNames.first;
	string paramName = varNames.second;

	unsigned structStartSuffix = m_structCounter + 1;
	if (auto st = findStruct(_type))
	{
		StructDeclVisitor sVisitor(structStartSuffix);
		global << sVisitor.visit(*st);
		m_structCounter = structStartSuffix + sVisitor.numStructs();
	}

	string type = TypeVisitor(structStartSuffix).visit(_type);

	// variable declaration
	if (m_isStateVar)
		global << appendVarDeclToOutput(type, varName, getQualifier(_type));
	else
		local << appendVarDeclToOutput(type, varName, getQualifier(_type));

	// TODO: variable definition and checks
	pair<string, string> assignCheckStrPair = AssignCheckVisitor(
		m_varCounter - 1,
		m_isStateVar
		)
		.visit(_type);

	m_checks << assignCheckStrPair.second;

	// State variables cannot be assigned in contract-scope
	// Therefore, we buffer their assignments and
	// render them in function scope later.
	local << assignCheckStrPair.first;

	// Add typed params for calling public and external functions with said type
	appendTypedParams(
		CalleeType::PUBLIC,
		isValueType(_type),
		type,
		paramName,
		((m_varCounter == 1) ? Delimiter::SKIP : Delimiter::ADD)
	);
	appendTypedParams(
		CalleeType::EXTERNAL,
		isValueType(_type),
		type,
		paramName,
		((m_varCounter == 1) ? Delimiter::SKIP : Delimiter::ADD)
	);
	return make_pair(global.str(), local.str());
}
//
//void ProtoConverter::addVarDef(std::string const& _varName, std::string const& _rhs)
//{
//	std::string varDefString = Whiskers(R"(
//		<varName> = <rhs>;)"
//		)
//		("varName", _varName)
//		("rhs", _rhs)
//		.render();
//
//	// State variables cannot be assigned in contract-scope
//	// Therefore, we buffer their assignments and
//	// render them in function scope later.
//	if (m_isStateVar)
//		m_local << varDefString;
//	else
//		m_output << varDefString;
//}
//
//void ProtoConverter::addCheckedVarDef(
//	ComparisonBuiltIn _type,
//	std::string const& _varName,
//	std::string const& _paramName,
//	std::string const& _rhs)
//{
//	addVarDef(_varName, _rhs);
//	appendChecks(_type, _paramName, _rhs);
//}
//
//// Runtime check for array length.
//void ProtoConverter::checkResizeOp(std::string const& _paramName, unsigned _len)
//{
//	appendChecks(ComparisonBuiltIn::VALUE, _paramName + ".length", std::to_string(_len));
//}

//string ProtoConverter::arrayDimInfoAsString(ArrayDimensionInfo const& _x)
//{
//	return Whiskers(R"([<?isStatic><length></isStatic>])")
//		("isStatic", _x.is_static())
//		("length", std::to_string(getStaticArrayLengthFromFuzz(_x.length())))
//		.render();
//}

//void ProtoConverter::arrayDimensionsAsStringVector(
//	ArrayType const& _x,
//	std::vector<std::string>& _vecOfStr)
//{
//	solAssert(_x.info_size() > 0, "Proto ABIv2 Fuzzer: Array dimensions empty.");
//	for (auto const& dim: _x.info())
//		_vecOfStr.push_back(arrayDimInfoAsString(dim));
//}

//ProtoConverter::VecOfBoolUnsigned ProtoConverter::arrayDimensionsAsPairVector(
//	ArrayType const& _x
//)
//{
//	VecOfBoolUnsigned arrayDimsPairVector = {};
//	for (auto const& dim: _x.info())
//		arrayDimsPairVector.push_back(arrayDimInfoAsPair(dim));
//	solAssert(!arrayDimsPairVector.empty(), "Proto ABIv2 Fuzzer: Array dimensions empty.");
//	return arrayDimsPairVector;
//}
//
//std::string ProtoConverter::getValueByBaseType(ArrayType const& _x)
//{
//	switch (_x.base_type_oneof_case())
//	{
//	case ArrayType::kInty:
//		return integerValueAsString(isIntSigned(_x.inty()), getIntWidth(_x.inty()), getNextCounter());
//	case ArrayType::kByty:
//		return fixedByteValueAsString(getFixedByteWidth(_x.byty()), getNextCounter());
//	case ArrayType::kAdty:
//		return addressValueAsString(getNextCounter());
//	case ArrayType::kBoolty:
//		return boolValueAsString(getNextCounter());
//	case ArrayType::kDynbytesty:
//		return bytesArrayValueAsString(
//			getNextCounter(),
//			_x.dynbytesty().type() == DynamicByteArrayType::BYTES
//		);
//	case ArrayType::kStty:
//		m_structBaseType = true;
//		return "";
//	case ArrayType::BASE_TYPE_ONEOF_NOT_SET:
//		solAssert(false, "Proto ABIv2 fuzzer: Invalid array base type");
//	}
//}

//ProtoConverter::ComparisonBuiltIn ProtoConverter::getDataTypeByBaseType(ArrayType const& _x)
//{
//	switch (_x.base_type_oneof_case())
//	{
//	case ArrayType::kInty:
//	case ArrayType::kByty:
//	case ArrayType::kAdty:
//	case ArrayType::kBoolty:
//		return ComparisonBuiltIn::VALUE;
//	case ArrayType::kDynbytesty:
//		return getDataTypeOfDynBytesType(_x.dynbytesty());
//	case ArrayType::kStty:
//	case ArrayType::BASE_TYPE_ONEOF_NOT_SET:
//		solUnimplemented("Proto ABIv2 fuzzer: Invalid array base type");
//	}
//}
//
//// Adds a resize operation for a given dimension of type `_type` and expression referenced
//// by `_var`. `_isStatic` is true for statically sized dimensions, false otherwise.
//// `_arrayLen` is equal to length of statically sized array dimension. For dynamically
//// sized dimension, we use `getDynArrayLengthFromFuzz()` and a monotonically increasing
//// counter to obtain actual length. Function returns dimension length.
//unsigned ProtoConverter::resizeDimension(
//	bool _isStatic,
//	unsigned _arrayLen,
//	std::string const& _var,
//	std::string const& _param,
//	std::string const& _type
//)
//{
//	unsigned length;
//	if (_isStatic)
//		length = _arrayLen;
//	else
//	{
//		length = getDynArrayLengthFromFuzz(_arrayLen, getNextCounter());
//
//		// If local var, new T(l);
//		// Else, l;
//		std::string lhs, rhs;
//		if (m_isStateVar)
//		{
//			lhs = _var + ".length";
//			rhs = Whiskers(R"(<length>)")
//				("length", std::to_string(length))
//				.render();
//		}
//		else
//		{
//			lhs = _var;
//			rhs = Whiskers(R"(new <type>(<length>))")
//				("type", _type)
//				("length", std::to_string(length))
//				.render();
//		}
//		// If local var, x = new T(l);
//		// Else, x.length = l;
//		addVarDef(lhs, rhs);
//	}
//
//	// if (c.length != l)
//	checkResizeOp(_param, length);
//	return length;
//}
//
//void ProtoConverter::resizeHelper(
//	ArrayType const& _x,
//	std::vector<std::string> _arrStrVec,
//	VecOfBoolUnsigned _arrInfoVec,
//	std::string const& _varName,
//	std::string const& _paramName
//)
//{
//	// Initialize value expressions if we have arrived at leaf node,
//	// (depth-first) recurse otherwise.
//	if (_arrInfoVec.empty())
//	{
//		// expression name is _var
//		// value is a value of base type
//		std::string value = getValueByBaseType(_x);
//		// add assignment and check
//		ComparisonBuiltIn dataType = getDataTypeByBaseType(_x);
//		addCheckedVarDef(dataType, _varName, _paramName, value);
//	}
//	else
//	{
//		auto& dim = _arrInfoVec.back();
//
//		std::string type = std::accumulate(
//			_arrStrVec.begin(),
//			_arrStrVec.end(),
//			std::string("")
//		);
//		unsigned length = resizeDimension(dim.first, dim.second, _varName, _paramName, type);
//		// Recurse one level dimension down.
//		_arrStrVec.pop_back();
//		_arrInfoVec.pop_back();
//		for (unsigned i = 0; i < length; i++)
//			resizeHelper(
//				_x,
//				_arrStrVec,
//				_arrInfoVec,
//				_varName + "[" + std::to_string(i) + "]",
//				_paramName + "[" + std::to_string(i) + "]"
//			);
//	}
//}
//
//// This function takes care of properly resizing and initializing ArrayType.
//// In parallel, it adds runtime checks on array bound and values.
//void ProtoConverter::resizeInitArray(
//	ArrayType const& _x,
//	std::string const& _baseType,
//	std::string const& _varName,
//	std::string const& _paramName
//)
//{
//	VecOfBoolUnsigned arrInfoVec = arrayDimensionsAsPairVector(_x);
//	std::vector<std::string> arrStrVec = {_baseType};
//	arrayDimensionsAsStringVector(_x, arrStrVec);
//	resizeHelper(_x, arrStrVec, arrInfoVec, _varName, _paramName);
//}
//
//// Returns array type from it's base type (e.g., int8) and array dimensions info contained in
//// ArrayType.
//std::string ProtoConverter::arrayTypeAsString(std::string const& _baseType, ArrayType const& _x)
//{
//	std::vector<std::string> typeStringVec = {_baseType};
//	arrayDimensionsAsStringVector(_x, typeStringVec);
//
//	return std::accumulate(
//		typeStringVec.begin(),
//		typeStringVec.end(),
//		std::string("")
//	);
//}
//
//void ProtoConverter::visit(ArrayType const& _x)
//{
//	// Bail out if input contains too few or too many dimensions.
//	if (_x.info_size() == 0 || _x.info_size() > (int)s_maxArrayDimensions)
//		return;
//
//	// Array type is dynamically encoded if one of the following is true
//	//   - array base type is "bytes" or "string"
//	//   - at least one array dimension is dynamically sized.
//	if (_x.base_type_oneof_case() == ArrayType::kDynbytesty)
//		m_isLastDynParamRightPadded = true;
//	else
//		for (auto const& dim: _x.info())
//			if (!dim.is_static())
//			{
//				m_isLastDynParamRightPadded = true;
//				break;
//			}
//
//	string baseType = {};
//	switch (_x.base_type_oneof_case())
//	{
//	case ArrayType::kInty:
//		baseType = getIntTypeAsString(_x.inty());
//		break;
//	case ArrayType::kByty:
//		baseType = getFixedByteTypeAsString(_x.byty());
//		break;
//	case ArrayType::kAdty:
//		baseType = getAddressTypeAsString(_x.adty());
//		break;
//	case ArrayType::kBoolty:
//		baseType = getBoolTypeAsString();
//		break;
//	case ArrayType::kDynbytesty:
//		baseType = bytesArrayTypeAsString(_x.dynbytesty());
//		break;
//	case ArrayType::kStty:
//	case ArrayType::BASE_TYPE_ONEOF_NOT_SET:
//		return;
//	}
//	visitArrayType(baseType, _x);
//}

pair<string, string> ProtoConverter::visit(VarDecl const& _x)
{
	// For types except struct, this prints the
	// type string to stream.
	// For structs, this prints struct definitions.
	return visit(_x.type());

	// TODO: If _x.type() is a struct, then
	// we must create a vardecl of the outer most
	// struct type S0.
	//	if (_x.type().has_nvtype() && _x.type().nvtype().has_stype())

	// TODO: If vardecl not in storage and is of
	// non-value type, then set location to memory
	// TODO: If vardecl is of non value type, then
	// set parameter location as "memory" and
	// "calldata" for the public and external
	// functions respectively.

	// if (m_isStorage) don't add location
	// else add location according to type
	// createVarDecl(typeStream, location, varSuffix);
	// AssignmentVisitor{_x.type()}.print(assignStream);
	// createAssignment(assignStream);
//	visit(_x.type());
}

std::string ProtoConverter::equalityChecksAsString()
{
	return m_checks.str();
}

std::string ProtoConverter::delimiterToString(Delimiter _delimiter)
{
	switch (_delimiter)
	{
	case Delimiter::ADD:
		return ", ";
	case Delimiter::SKIP:
		return "";
	}
}

/* When a new variable is declared, we can invoke this function
 * to prepare the typed param list to be passed to callee functions.
 * We independently prepare this list for "public" and "external"
 * callee functions.
 */
void ProtoConverter::appendTypedParams(
	CalleeType _calleeType,
	bool _isValueType,
	std::string const& _typeString,
	std::string const& _varName,
	Delimiter _delimiter
)
{
	switch (_calleeType)
	{
	case CalleeType::PUBLIC:
		appendTypedParamsPublic(_isValueType, _typeString, _varName, _delimiter);
		break;
	case CalleeType::EXTERNAL:
		appendTypedParamsExternal(_isValueType, _typeString, _varName, _delimiter);
		break;
	}
}

// Adds the qualifier "calldata" to non-value parameter of an external function.
void ProtoConverter::appendTypedParamsExternal(
	bool _isValueType,
    std::string const& _typeString,
    std::string const& _varName,
    Delimiter _delimiter
)
{
	std::string qualifiedTypeString = (
		_isValueType ?
		_typeString :
		_typeString + " calldata"
	);
	m_typedParamsExternal << Whiskers(R"(<delimiter><type> <varName>)")
		("delimiter", delimiterToString(_delimiter))
		("type", qualifiedTypeString)
		("varName", _varName)
		.render();
}

// Adds the qualifier "memory" to non-value parameter of an external function.
void ProtoConverter::appendTypedParamsPublic(
	bool _isValueType,
	std::string const& _typeString,
	std::string const& _varName,
	Delimiter _delimiter
)
{
	std::string qualifiedTypeString = (
		_isValueType ?
		_typeString :
		_typeString + " memory"
		);
	m_typedParamsPublic << Whiskers(R"(<delimiter><type> <varName>)")
		("delimiter", delimiterToString(_delimiter))
		("type", qualifiedTypeString)
		("varName", _varName)
		.render();
}

std::string ProtoConverter::typedParametersAsString(CalleeType _calleeType)
{
	switch (_calleeType)
	{
	case CalleeType::PUBLIC:
		return m_typedParamsPublic.str();
	case CalleeType::EXTERNAL:
		return m_typedParamsExternal.str();
	}
}

/// Test function to be called externally.
pair<string, string> ProtoConverter::visit(TestFunction const& _x)
{
	ostringstream global, local;
	// TODO: Support more than one but less than N local variables
	auto localVarBuffers = visit(_x.local_vars());

	global << localVarBuffers.first;
	global << R"(
	function test() public returns (uint) {)"
	       << endl;

	global << localVarBuffers.second;
	global << testCode(_x.invalid_encoding_length());
	global << R"(
	})" <<
		endl;
	return make_pair(global.str(), local.str());
}

string ProtoConverter::testCode(unsigned _invalidLength)
{
	return Whiskers(R"(
		uint returnVal = this.coder_public(<parameterNames>);
		if (returnVal != 0)
			return returnVal;

		returnVal = this.coder_external(<parameterNames>);
		if (returnVal != 0)
			return uint(200000) + returnVal;

		<?atLeastOneVar>
		bytes memory argumentEncoding = abi.encode(<parameterNames>);

		returnVal = checkEncodedCall(
			this.coder_public.selector,
			argumentEncoding,
			<invalidLengthFuzz>,
			<isRightPadded>
		);
		if (returnVal != 0)
			return returnVal;

		returnVal = checkEncodedCall(
			this.coder_external.selector,
			argumentEncoding,
			<invalidLengthFuzz>,
			<isRightPadded>
		);
		if (returnVal != 0)
			return uint(200000) + returnVal;
		</atLeastOneVar>
		return 0;
	)")
		("parameterNames", dev::suffixedVariableNameList(s_varNamePrefix, 0, m_varCounter))
		("invalidLengthFuzz", std::to_string(_invalidLength))
		("isRightPadded", isLastDynParamRightPadded() ? "true" : "false")
		("atLeastOneVar", m_varCounter > 0)
		.render();
}

string ProtoConverter::helperFunctions()
{
	stringstream helperFuncs;
	helperFuncs << R"(
	function bytesCompare(bytes memory a, bytes memory b) internal pure returns (bool) {
		if(a.length != b.length)
			return false;
		for (uint i = 0; i < a.length; i++)
			if (a[i] != b[i])
				return false;
		return true;
	}

	/// Accepts function selector, correct argument encoding, and length of
	/// invalid encoding and returns the correct and incorrect abi encoding
	/// for calling the function specified by the function selector.
	function createEncoding(
		bytes4 funcSelector,
		bytes memory argumentEncoding,
		uint invalidLengthFuzz,
		bool isRightPadded
	) internal pure returns (bytes memory, bytes memory)
	{
		bytes memory validEncoding = new bytes(4 + argumentEncoding.length);
		// Ensure that invalidEncoding crops at least 32 bytes (padding length
		// is at most 31 bytes) if `isRightPadded` is true.
		// This is because shorter bytes/string values (whose encoding is right
		// padded) can lead to successful decoding when fewer than 32 bytes have
		// been cropped in the worst case. In other words, if `isRightPadded` is
		// true, then
		//  0 <= invalidLength <= argumentEncoding.length - 32
		// otherwise
		//  0 <= invalidLength <= argumentEncoding.length - 1
		uint invalidLength;
		if (isRightPadded)
			invalidLength = invalidLengthFuzz % (argumentEncoding.length - 31);
		else
			invalidLength = invalidLengthFuzz % argumentEncoding.length;
		bytes memory invalidEncoding = new bytes(4 + invalidLength);
		for (uint i = 0; i < 4; i++)
			validEncoding[i] = invalidEncoding[i] = funcSelector[i];
		for (uint i = 0; i < argumentEncoding.length; i++)
			validEncoding[i+4] = argumentEncoding[i];
		for (uint i = 0; i < invalidLength; i++)
			invalidEncoding[i+4] = argumentEncoding[i];
		return (validEncoding, invalidEncoding);
	}

	/// Accepts function selector, correct argument encoding, and an invalid
	/// encoding length as input. Returns a non-zero value if either call with
	/// correct encoding fails or call with incorrect encoding succeeds.
	/// Returns zero if both calls meet expectation.
	function checkEncodedCall(
		bytes4 funcSelector,
		bytes memory argumentEncoding,
		uint invalidLengthFuzz,
		bool isRightPadded
	) public returns (uint)
	{
		(bytes memory validEncoding, bytes memory invalidEncoding) = createEncoding(
			funcSelector,
			argumentEncoding,
			invalidLengthFuzz,
			isRightPadded
		);
		(bool success, bytes memory returnVal) = address(this).call(validEncoding);
		uint returnCode = abi.decode(returnVal, (uint));
		// Return non-zero value if call fails for correct encoding
		if (success == false || returnCode != 0)
			return 400000;
		(success, ) = address(this).call(invalidEncoding);
		// Return non-zero value if call succeeds for incorrect encoding
		if (success == true)
			return 400001;
		return 0;
	}
	)";

	// These are callee functions that encode from storage, decode to
	// memory/calldata and check if decoded value matches storage value
	// return true on successful match, false otherwise
	helperFuncs << Whiskers(R"(
	function coder_public(<parameters_memory>) public pure returns (uint) {
<equality_checks>
		return 0;
	}

	function coder_external(<parameters_calldata>) external pure returns (uint) {
<equality_checks>
		return 0;
	}
	)")
	("parameters_memory", typedParametersAsString(CalleeType::PUBLIC))
	("equality_checks", equalityChecksAsString())
	("parameters_calldata", typedParametersAsString(CalleeType::EXTERNAL))
	.render();
	return helperFuncs.str();
}

void ProtoConverter::visit(Contract const& _x)
{
	string pragmas = R"(pragma solidity >=0.0;
pragma experimental ABIEncoderV2;)";

	// TODO: Support more than one but less than N state variables
	auto stateBuffers = visit(_x.state_vars());
	m_isStateVar = false;
	auto localBuffers = visit(_x.testfunction());
	ostringstream contractBody;
	/*
	 * Storage variable declarations
	 * Struct type declarations
	 * Storage variable definitions
	 * Local variable definitions
	 * Helper functions
	 */

	contractBody << stateBuffers.first
		<< localBuffers.first
		<< stateBuffers.second
		<< helperFunctions();
	m_output << Whiskers(R"(<pragmas>
<contractStart>
<contractBody>
<contractEnd>)")
		("pragmas", pragmas)
		("contractStart", "contract C {")
		("contractBody", contractBody.str())
		("contractEnd", "}")
		.render();
}

string ProtoConverter::contractToString(Contract const& _input)
{
	visit(_input);
	return m_output.str();
}

/// Type visitor
string TypeVisitor::visit(BoolType const&)
{
	return "bool";
}

string TypeVisitor::visit(IntegerType const& _type)
{
	return getIntTypeAsString(_type);
}

string TypeVisitor::visit(FixedByteType const& _type)
{
	return getFixedByteTypeAsString(_type);
}

string TypeVisitor::visit(AddressType const& _type)
{
	return getAddressTypeAsString(_type);
}

string TypeVisitor::visit(ArrayType const& _type)
{
	// Convention: Protobuf array type specifies array
	// dimension in reverse order i.e., outer most to
	// inner most.
	// Example: 2,3,4 (all statically sized) will print
	// x[4][3][2]
	string baseType = visit(_type.t());
	string arrayBraces = _type.is_static() ?
		string("[") +
		to_string(getStaticArrayLengthFromFuzz(_type.length())) +
		string("]") :
		string("[]");
	m_array << arrayBraces;
	return baseType + arrayBraces;
}

string TypeVisitor::visit(DynamicByteArrayType const& _type)
{
	return bytesArrayTypeAsString(_type);
}

string TypeVisitor::visit(StructType const&)
{
	return s_structTypeName + to_string(m_structSuffix);
}

/// StructDeclVisitor implementation
string StructDeclVisitor::visit(StructType const& _type)
{
	string structDecl = lineString("struct S" + to_string(m_structCounter++) + " {");
	m_indentation++;
	for (auto const& t: _type.t())
	{
		string type;
		if (t.has_nvtype() && t.nvtype().has_stype())
		{
			m_type << StructDeclVisitor{m_structCounter}.visit(t.nvtype().stype());
			type = "S" + to_string(m_structCounter);
		}
		else
			type = visit(t);
		structDecl += lineString(
			Whiskers(R"(<type> <member>;)")
				("type", type)
				("member", "m" + to_string(m_structFieldCounter++))
				.render()
		);
	}
	m_indentation--;
	structDecl += lineString("}");
	structDecl += m_type.str();
	return structDecl;
}

/// AssignCheckVisitor implementation
pair<string, string> AssignCheckVisitor::visit(BoolType const& _type)
{
	string value = ValueGetterVisitor().visit(_type);
	return assignAndCheckStringPair(m_varName, m_paramName, value, DataType::VALUE);
}

pair<string, string> AssignCheckVisitor::visit(IntegerType const& _type)
{
	string value = ValueGetterVisitor().visit(_type);
	return assignAndCheckStringPair(m_varName, m_paramName, value, DataType::VALUE);
}

pair<string, string> AssignCheckVisitor::visit(FixedByteType const& _type)
{
	string value = ValueGetterVisitor().visit(_type);
	return assignAndCheckStringPair(m_varName, m_paramName, value, DataType::VALUE);
}

pair<string, string> AssignCheckVisitor::visit(AddressType const& _type)
{
	string value = ValueGetterVisitor().visit(_type);
	return assignAndCheckStringPair(m_varName, m_paramName, value, DataType::VALUE);
}

pair<string, string> AssignCheckVisitor::visit(DynamicByteArrayType const& _type)
{
	string value = ValueGetterVisitor().visit(_type);
	return assignAndCheckStringPair(m_varName, m_paramName, value, DataType::VALUE);
}

//string AssignCheckVisitor::visit(ArrayType const& _type)
//{
//	ostringstream qualBaseType;
//	TypeVisitor t = TypeVisitor{_type.t()};
//	t.print(qualBaseType);
//	string qualType = t.m_array.str();
//	unsigned arrayDimensionSize;
//	if (_type.is_static())
//		arrayDimensionSize = getStaticArrayLengthFromFuzz(_type.length());
//	else
//	{
//		arrayDimensionSize = getDynArrayLengthFromFuzz(_type.length(), counter());
//		if (qualType.empty())
//			assignString(
//				m_varName,
//
//			);
//		assignString(
//			m_varName + qualType,
//			"new " + t.m_array
//		);
//	}
//
//	checkString(
//		m_paramName + t.m_array + ".length",
//		arrayDimensionSize,
//		ComparisonBuiltIn::VALUE
//	);
//
//
//	// Resize only if dynamically sized
//	if (m_stateVar)
//		assignAndCheckStringPair(
//			m_varName + ".length",
//			m_paramName + ".length",
//			length,
//			ComparisonBuiltIn::ARRAY
//		);
//	else
//	{
//		ostringstream arrayType;
//		TypeVisitor{*m_type}.print(arrayType);
//
//
//		assignString(typeStr, typeStr(length));
//		checkString(typeStr, typeStr(length));
//	}
//	//	for (0..arrayDimensionSize) visit()
//}
//
//string AssignCheckVisitor::visit(DynamicByteArrayType const& _type)
//{
//	bool isBytes = _type.type() == DynamicByteArrayType::BYTES;
//	string value = bytesArrayValueAsString(counter(), isBytes);
//	assignString(m_varName, value);
//	checkString(m_paramName, value, ComparisonBuiltIn::VALUE);
//	// Update right padding of type
//	m_isLastDynParamRightPadded = true;
//	return true;
//}
//

// FIXME: Implement these
pair<string, string> AssignCheckVisitor::visit(ArrayType const&)
{
	return make_pair("", "");
}

pair<string, string> AssignCheckVisitor::visit(StructType const&)
{
	return make_pair("", "");
}

pair<string, string> AssignCheckVisitor::assignAndCheckStringPair(
	string const& _varRef,
	string const& _checkRef,
	string const& _value,
	DataType _type
)
{
	return make_pair(assignString(_varRef, _value), checkString(_checkRef, _value, _type));
}

string AssignCheckVisitor::assignString(string const& _ref, string const& _value)
{
	string assignStmt = Whiskers(R"(<ref> = <value>;)")
		("ref", _ref)
		("value", _value)
		.render();
	return indentation() + assignStmt + "\n";
}

string AssignCheckVisitor::checkString(string const& _ref, string const& _value, DataType _type)
{
	string checkPred;
	switch (_type)
	{
	case DataType::STRING:
		checkPred = Whiskers(R"(!bytesCompare(bytes(<varName>), <value>))")
			("varName", _ref)
			("value", _value)
			.render();
		break;
	case DataType::BYTES:
		checkPred = Whiskers(R"(!bytesCompare(<varName>, <value>))")
			("varName", _ref)
			("value", _value)
			.render();
		break;
	case DataType::VALUE:
		checkPred = Whiskers(R"(<varName> != <value>)")
			("varName", _ref)
			("value", _value)
			.render();
		break;
	case DataType::ARRAY:
		solUnimplemented("Proto ABIv2 fuzzer: Invalid data type.");
	}
	string checkStmt = Whiskers(R"(if (<checkPred>) return <errCode>;)")
		("checkPred", checkPred)
		("errCode", to_string(++m_errorCode))
		.render();
	return indentation() + checkStmt + "\n";
}

/// ValueGetterVisitor
string ValueGetterVisitor::visit(BoolType const&)
{
	return counter() % 2 ? "true" : "false";
}

string ValueGetterVisitor::visit(IntegerType const& _type)
{
	return integerValueAsString(
		_type.is_signed(),
		getIntWidth(_type),
		counter()
	);
}

string ValueGetterVisitor::visit(FixedByteType const& _type)
{
	return fixedByteValueAsString(
		getFixedByteWidth(_type),
		counter()
	);
}

string ValueGetterVisitor::visit(AddressType const&)
{
	return addressValueAsString(counter());
}

string ValueGetterVisitor::visit(DynamicByteArrayType const& _type)
{
	return bytesArrayValueAsString(
		counter(),
		getDataTypeOfDynBytesType(_type) == DataType::BYTES
	);
}

std::string ValueGetterVisitor::integerValueAsString(bool _sign, unsigned _width, unsigned _counter)
{
	if (_sign)
		return intValueAsString(_width, _counter);
	else
		return uintValueAsString(_width, _counter);
}

/* Input(s)
 *   - Unsigned integer to be hashed
 *   - Width of desired uint value
 * Processing
 *   - Take hash of first parameter and mask it with the max unsigned value for given bit width
 * Output
 *   - string representation of uint value
 */
std::string ValueGetterVisitor::uintValueAsString(unsigned _width, unsigned _counter)
{
	solAssert(
		(_width % 8 == 0),
		"Proto ABIv2 Fuzzer: Unsigned integer width is not a multiple of 8"
	);
	return maskUnsignedIntToHex(_counter, _width/4);
}

/* Input(s)
 *   - counter to be hashed to derive a value for Integer type
 *   - Width of desired int value
 * Processing
 *   - Take hash of first parameter and mask it with the max signed value for given bit width
 * Output
 *   - string representation of int value
 */
std::string ValueGetterVisitor::intValueAsString(unsigned _width, unsigned _counter)
{
	solAssert(
		(_width % 8 == 0),
		"Proto ABIv2 Fuzzer: Signed integer width is not a multiple of 8"
	);
	return maskUnsignedIntToHex(_counter, ((_width/4) - 1));
}

std::string ValueGetterVisitor::croppedString(
	unsigned _numBytes,
	unsigned _counter,
	bool _isHexLiteral
)
{
	solAssert(
		_numBytes > 0 && _numBytes <= 32,
		"Proto ABIv2 fuzzer: Too short or too long a cropped string"
	);

	// Number of masked nibbles is twice the number of bytes for a
	// hex literal of _numBytes bytes. For a string literal, each nibble
	// is treated as a character.
	unsigned numMaskNibbles = _isHexLiteral ? _numBytes * 2 : _numBytes;

	// Start position of substring equals totalHexStringLength - numMaskNibbles
	// totalHexStringLength = 64 + 2 = 66
	// e.g., 0x12345678901234567890123456789012 is a total of 66 characters
	//      |---------------------^-----------|
	//      <--- start position---><--numMask->
	//      <-----------total length --------->
	// Note: This assumes that maskUnsignedIntToHex() invokes toHex(..., HexPrefix::Add)
	unsigned startPos = 66 - numMaskNibbles;
	// Extracts the least significant numMaskNibbles from the result
	// of maskUnsignedIntToHex().
	return maskUnsignedIntToHex(
		_counter,
		numMaskNibbles
	).substr(startPos, numMaskNibbles);
}

std::string ValueGetterVisitor::hexValueAsString(
	unsigned _numBytes,
	unsigned _counter,
	bool _isHexLiteral,
	bool _decorate
)
{
	solAssert(_numBytes > 0 && _numBytes <= 32,
	          "Proto ABIv2 fuzzer: Invalid hex length"
	);

	// If _decorate is set, then we return a hex"" or a "" string.
	if (_numBytes == 0)
		return Whiskers(R"(<?decorate><?isHex>hex</isHex>""</decorate>)")
			("decorate", _decorate)
			("isHex", _isHexLiteral)
			.render();

	// This is needed because solidity interprets a 20-byte 0x prefixed hex literal as an address
	// payable type.
	return Whiskers(R"(<?decorate><?isHex>hex</isHex>"</decorate><value><?decorate>"</decorate>)")
		("decorate", _decorate)
		("isHex", _isHexLiteral)
		("value", croppedString(_numBytes, _counter, _isHexLiteral))
		.render();
}

std::string ValueGetterVisitor::fixedByteValueAsString(unsigned _width, unsigned _counter)
{
	solAssert(
		(_width >= 1 && _width <= 32),
		"Proto ABIv2 Fuzzer: Fixed byte width is not between 1--32"
	);
	return hexValueAsString(_width, _counter, /*isHexLiteral=*/true);
}

std::string ValueGetterVisitor::addressValueAsString(unsigned _counter)
{
	return Whiskers(R"(address(<value>))")
		("value", uintValueAsString(160, _counter))
		.render();
}

std::string ValueGetterVisitor::variableLengthValueAsString(
	unsigned _numBytes,
	unsigned _counter,
	bool _isHexLiteral
)
{
	// TODO: Move this to caller
//	solAssert(_numBytes >= 0 && _numBytes <= s_maxDynArrayLength,
//	          "Proto ABIv2 fuzzer: Invalid hex length"
//	);
	if (_numBytes == 0)
		return Whiskers(R"(<?isHex>hex</isHex>"")")
			("isHex", _isHexLiteral)
			.render();

	unsigned numBytesRemaining = _numBytes;
	// Stores the literal
	string output{};
	// If requested value is shorter than or exactly 32 bytes,
	// the literal is the return value of hexValueAsString.
	if (numBytesRemaining <= 32)
		output = hexValueAsString(
			numBytesRemaining,
			_counter,
			_isHexLiteral,
			/*decorate=*/false
		);
		// If requested value is longer than 32 bytes, the literal
		// is obtained by duplicating the return value of hexValueAsString
		// until we reach a value of the requested size.
	else
	{
		// Create a 32-byte value to be duplicated and
		// update number of bytes to be appended.
		// Stores the cached literal that saves us
		// (expensive) calls to keccak256.
		string cachedString = hexValueAsString(
			/*numBytes=*/32,
			             _counter,
			             _isHexLiteral,
			/*decorate=*/false
		);
		output = cachedString;
		numBytesRemaining -= 32;

		// Append bytes from cachedString until
		// we create a value of desired length.
		unsigned numAppendedBytes;
		while (numBytesRemaining > 0)
		{
			// We append at most 32 bytes at a time
			numAppendedBytes = numBytesRemaining >= 32 ? 32 : numBytesRemaining;
			output += cachedString.substr(
				0,
				// Double the substring length for hex literals since each
				// character is actually half a byte (or a nibble).
				_isHexLiteral ? numAppendedBytes * 2 : numAppendedBytes
			);
			numBytesRemaining -= numAppendedBytes;
		}
		solAssert(
			numBytesRemaining == 0,
			"Proto ABIv2 fuzzer: Logic flaw in variable literal creation"
		);
	}

	if (_isHexLiteral)
		solAssert(
			output.size() == 2 * _numBytes,
			"Proto ABIv2 fuzzer: Generated hex literal is of incorrect length"
		);
	else
		solAssert(
			output.size() == _numBytes,
			"Proto ABIv2 fuzzer: Generated string literal is of incorrect length"
		);

	// Decorate output
	return Whiskers(R"(<?isHexLiteral>hex</isHexLiteral>"<value>")")
		("isHexLiteral", _isHexLiteral)
		("value", output)
		.render();
}

string ValueGetterVisitor::bytesArrayValueAsString(unsigned _counter, bool _isHexLiteral)
{
	return variableLengthValueAsString(
		getVarLength(_counter),
		_counter,
		_isHexLiteral
	);
}