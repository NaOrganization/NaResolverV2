//**************************************//
// Hi NaResolver						//
// Author: MidTerm                   	//
// Version: v2.0.0                      //
// Branch: Mono							//
// License: MIT                         //
//**************************************//

#if !_HAS_CXX17
#pragma message("The contents of NaResolver are available only with C++17 or later.")
#else

#undef GetClassName

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <codecvt>

typedef void MonoDomain;
typedef void MonoAssembly;
typedef void MonoClass;
typedef void MonoThread;
typedef void MonoImage;
typedef void MonoString;
typedef void MonoMethod;
typedef void MonoType;
typedef void MonoMethodSignature;
typedef void MonoAssemblyName;
typedef void MonoClassField;
typedef void* MonoMethodPointer;
typedef int32_t        gboolean;
typedef int32_t			mono_bool;

class MonoManager
{
public:
	HMODULE assemblyModule;
	std::unordered_map<std::string, void*> monoMethodMap =
	{
		{"mono_get_root_domain", nullptr},					//MonoDomain*(void);
		{"mono_domain_assembly_open", nullptr},				//MonoAssembly*(MonoDomain *domain, const char *name);

		{"mono_type_get_name", nullptr},					//char*(MonoType *type);
		{"mono_type_is_byref", nullptr},					//mono_bool(MonoType *type);
		{"mono_type_get_attrs", nullptr},					//uint32_t(MonoType *type);
		{"mono_type_get_class", nullptr},					//MonoClass*(MonoType *type);

		{"mono_thread_attach", nullptr},					//MonoThread*(MonoDomain *domain);
		{"mono_thread_detach", nullptr},					//void(MonoThread *thread);

		{"mono_string_new", nullptr},						//MonoString* (MonoDomain * domain, const char *text)
		{"mono_string_chars", nullptr},						//uint16_t* (MonoString * s)
		{"mono_string_length", nullptr},					//int (MonoString * s)

		{"mono_class_get_methods", nullptr},				//MonoMethod*(MonoClass* klass, void **iter);
		{"mono_class_from_name", nullptr},					//MonoClass *(MonoImage *image, const char* name_space, const char *name);
		{"mono_class_get_name", nullptr},					//const char*(MonoClass *klass);
		{"mono_class_get_namespace", nullptr},				//const char*(MonoClass *klass);
		{"mono_class_get_image", nullptr},					//MonoImage*(MonoClass *klass);			
		{"mono_class_get_fields", nullptr},					//MonoClassField*(MonoClass* klass, void **iter);
		{"mono_class_get_parent", nullptr},					//MonoClass *(MonoClass *klass);
		{"mono_class_get_nested_types", nullptr},			//MonoClass*(MonoClass* klass, void **iter);
		{"mono_class_get_flags", nullptr},					//uint32_t(MonoClassField *field);
		{"mono_class_is_generic", nullptr},					//gboolean(MonoClass *klass);
		{"mono_class_is_enum", nullptr},					//mono_bool(MonoClass *klass);
		{"mono_class_is_valuetype", nullptr},				//mono_bool(MonoClass *klass);
		{"mono_class_from_mono_type", nullptr},				//MonoClass *(MonoType *type);
		{"mono_class_get_type", nullptr},					//MonoType*(MonoClass *klass);
		{"mono_class_get_element_class", nullptr},			//MonoClass*(MonoClass *klass);

		{"mono_assembly_get_image", nullptr},				//MonoImage(MonoAssembly *assembly);
		{"mono_assembly_get_name", nullptr},				//MonoAssemblyName*(MonoAssembly *assembly);

		{"mono_assembly_name_get_name", nullptr},			//const char*(MonoAssemblyName*);

		{"mono_method_get_name", nullptr},					//const char*(MonoMethod *method);
		{"mono_method_signature", nullptr},					//MonoMethodSignature*(MonoMethod *method);
		{"mono_method_get_flags", nullptr},					//uint32_t(MonoMethod *method, uint32_t *iflags);
		{"mono_method_get_param_names", nullptr},			//->mono_method_get_param_name, void(MonoMethod *method, const char **names);

		{"mono_signature_get_return_type", nullptr},		//->mono_method_get_return_type, MonoType*(MonoMethodSignature *sig);
		{"mono_signature_get_param_count", nullptr},		//->mono_method_get_param_count, uint32_t(MonoMethodSignature *sig);
		{"mono_signature_get_params", nullptr},				//->mono_method_get_param, MonoType*(MonoMethodSignature *sig, void **iter);

		{"mono_image_get_assembly", nullptr},				//MonoAssembly*(MonoImage *image);

		{"mono_field_get_name", nullptr},					//const char*(MonoClassField *field);
		{"mono_field_get_flags", nullptr},					//uint32_t(MonoClassField *field);
		{"mono_field_get_type", nullptr},					//MonoType*(MonoClassField *field);
		{"mono_field_get_offset", nullptr},					//uint32_t(MonoClassField *field);
		
		{"mono_compile_method", nullptr},					//void* (MonoMethod *method);
	};

	inline void ImportMethods()
	{
		assemblyModule = GetModuleHandleW(L"mono-2.0-bdwgc.dll");
		if (!assemblyModule)
		{
			throw std::exception("Failed to get GameAssembly.dll module handle");
		}
		for (auto& m : monoMethodMap)
		{
			m.second = GetProcAddress(assemblyModule, m.first.c_str());
			if (!m.second)
			{
				throw std::exception(("Failed to get " + m.first + " function address").c_str());
			}
		}
	}

	inline MonoDomain* GetRootDomain() { return ((MonoDomain * (*)(void))monoMethodMap["mono_get_root_domain"])(); }
	inline MonoAssembly* OpenDomainAssembly(MonoDomain* domain, const char* path) { return ((MonoAssembly * (*)(MonoDomain*, const char*))monoMethodMap["mono_domain_assembly_open"])(domain, path); }
	
	inline char* GetTypeName(MonoType* type) { return ((char* (*)(MonoType*))monoMethodMap["mono_type_get_name"])(type); }
	inline mono_bool IsTypeByRef(MonoType* type) { return ((mono_bool(*)(MonoType*))monoMethodMap["mono_type_is_byref"])(type); }
	inline uint32_t GetTypeAttrs(MonoType* type) { return ((uint32_t(*)(MonoType*))monoMethodMap["mono_type_get_attrs"])(type); }
	inline MonoClass* GetTypeClass(MonoType* type) { return ((MonoClass * (*)(MonoType*))monoMethodMap["mono_type_get_class"])(type); }

	inline MonoThread* AttachThread(MonoDomain* domain) { return ((MonoThread * (*)(MonoDomain*))monoMethodMap["mono_thread_attach"])(domain); }
	inline void DetachThread(MonoThread* thread) { ((void(*)(MonoThread*))monoMethodMap["mono_thread_detach"])(thread); }
	
	inline MonoString* NewString(MonoDomain* domain, const char* text) { return ((MonoString * (*)(MonoDomain*, const char*))monoMethodMap["mono_string_new"])(domain, text); }
	inline uint16_t* GetStringChars(MonoString* str) { return ((uint16_t * (*)(MonoString*))monoMethodMap["mono_string_chars"])(str); }
	inline int GetStringLength(MonoString* str) { return ((int(*)(MonoString*))monoMethodMap["mono_string_length"])(str); }
	
	inline MonoMethod* GetClassMethods(MonoClass* klass, void** iter) { return ((MonoMethod * (*)(MonoClass*, void**))monoMethodMap["mono_class_get_methods"])(klass, iter); }
	inline MonoClass* GetClassFromName(MonoImage* image, const char* name_space, const char* name) { return ((MonoClass * (*)(MonoImage*, const char*, const char*))monoMethodMap["mono_class_from_name"])(image, name_space, name); }
	inline const char* GetClassName(MonoClass* klass) { return ((const char* (*)(MonoClass*))monoMethodMap["mono_class_get_name"])(klass); }
	inline const char* GetClassNamespace(MonoClass* klass) { return ((const char* (*)(MonoClass*))monoMethodMap["mono_class_get_namespace"])(klass); }
	inline MonoImage* GetClassImage(MonoClass* klass) { return ((MonoImage * (*)(MonoClass*))monoMethodMap["mono_class_get_image"])(klass); }
	inline MonoClassField* GetClassFields(MonoClass* klass, void** iter) { return ((MonoClassField * (*)(MonoClass*, void**))monoMethodMap["mono_class_get_fields"])(klass, iter); }
	inline MonoClass* GetClassParent(MonoClass* klass) { return ((MonoClass * (*)(MonoClass*))monoMethodMap["mono_class_get_parent"])(klass); }
	inline MonoClass* GetClassNestedTypes(MonoClass* klass, void** iter) { return ((MonoClass * (*)(MonoClass*, void**))monoMethodMap["mono_class_get_nested_types"])(klass, iter); }
	inline uint32_t GetClassFlags(MonoClass* klass) { return ((uint32_t(*)(MonoClass*))monoMethodMap["mono_class_get_flags"])(klass); }
	inline gboolean ClassIsGeneric(MonoClass* klass) { return ((gboolean(*)(MonoClass*))monoMethodMap["mono_class_is_generic"])(klass); }
	inline mono_bool ClassIsEnum(MonoClass* klass) { return ((mono_bool(*)(MonoClass*))monoMethodMap["mono_class_is_enum"])(klass); }
	inline mono_bool ClassIsValueType(MonoClass* klass) { return ((mono_bool(*)(MonoClass*))monoMethodMap["mono_class_is_valuetype"])(klass); }
	inline MonoClass* GetClassFromMonoType(MonoType* type) { return ((MonoClass * (*)(MonoType*))monoMethodMap["mono_class_from_mono_type"])(type); }
	inline MonoType* GetClassType(MonoClass* klass) { return ((MonoType * (*)(MonoClass*))monoMethodMap["mono_class_get_type"])(klass); }
	inline MonoClass* GetClassElementClass(MonoClass* klass) { return ((MonoClass * (*)(MonoClass*))monoMethodMap["mono_class_get_element_class"])(klass); }

	inline MonoImage* GetAssemblyImage(MonoAssembly* assembly) { return ((MonoImage * (*)(MonoAssembly*))monoMethodMap["mono_assembly_get_image"])(assembly); }
	inline MonoAssemblyName* GetAssemblyName(MonoAssembly* assembly) { return ((MonoAssemblyName * (*)(MonoAssembly*))monoMethodMap["mono_assembly_get_name"])(assembly); }
	
	inline const char* GetAssemblyNameName(MonoAssemblyName* assemblyName) { return ((const char* (*)(MonoAssemblyName*))monoMethodMap["mono_assembly_name_get_name"])(assemblyName); }
	
	inline const char* GetMethodName(MonoMethod* method) { return ((const char* (*)(MonoMethod*))monoMethodMap["mono_method_get_name"])(method); }
	inline MonoMethodSignature* GetMethodSignature(MonoMethod* method) { return ((MonoMethodSignature * (*)(MonoMethod*))monoMethodMap["mono_method_signature"])(method); }
	inline uint32_t GetMethodFlags(MonoMethod* method, uint32_t* iflags) { return ((uint32_t(*)(MonoMethod*, uint32_t*))monoMethodMap["mono_method_get_flags"])(method, iflags); }
	inline void GetMethodParamNames(MonoMethod* method, const char** names) { ((void(*)(MonoMethod*, const char**))monoMethodMap["mono_method_get_param_names"])(method, names); }
	inline MonoType* GetMethodReturnType(MonoMethod* method)
	{ 
		MonoMethodSignature* signature = GetMethodSignature(method);
		if (signature == nullptr)
		{
			return nullptr;
		}
		return ((MonoType * (*)(MonoMethodSignature*))monoMethodMap["mono_signature_get_return_type"])(signature);
	}
	inline uint32_t GetMethodParamCount(MonoMethod* method)
	{
		MonoMethodSignature* signature = GetMethodSignature(method);
		if (signature == nullptr)
		{
			return 0;
		}
		return ((uint32_t(*)(MonoMethodSignature*))monoMethodMap["mono_signature_get_param_count"])(signature);
	}
	inline MonoType* GetMethodParams(MonoMethod* method, void** iter)
	{
		MonoMethodSignature* signature = GetMethodSignature(method);
		if (signature == nullptr)
		{
			return nullptr;
		}
		return ((MonoType * (*)(MonoMethodSignature*, void**))monoMethodMap["mono_signature_get_params"])(signature, iter);
	}

	
	inline MonoAssembly* GetImageAssembly(MonoImage* image) { return ((MonoAssembly * (*)(MonoImage*))monoMethodMap["mono_image_get_assembly"])(image); }

	inline const char* GetFieldName(MonoClassField* field) { return ((const char* (*)(MonoClassField*))monoMethodMap["mono_field_get_name"])(field); }
	inline uint32_t GetFieldFlags(MonoClassField* field) { return ((uint32_t(*)(MonoClassField*))monoMethodMap["mono_field_get_flags"])(field); }
	inline MonoType* GetFieldType(MonoClassField* field) { return ((MonoType * (*)(MonoClassField*))monoMethodMap["mono_field_get_type"])(field); }
	inline uint32_t GetFieldOffset(MonoClassField* field) { return ((uint32_t(*)(MonoClassField*))monoMethodMap["mono_field_get_offset"])(field); }

	inline void* CompileMethod(MonoMethod* method) { return ((void* (*)(MonoMethod*))monoMethodMap["mono_compile_method"])(method); }
};


namespace Signature
{
	namespace Class
	{
		inline std::string Create(std::string assembly, std::string nameSpace, std::string name)
		{
			return std::string("(") + assembly + ")" + nameSpace + (nameSpace.empty() ? "" : ".") + name;
		}

		inline std::string Create(MonoClass* klass, MonoManager monoManager)
		{
			MonoImage* image = monoManager.GetClassImage(klass);
			if (!image)
				return std::string();
			MonoAssembly* assembly = monoManager.GetImageAssembly(image);
			if (!assembly)
				return std::string();
			MonoAssemblyName* assemblyName = monoManager.GetAssemblyName(assembly);
			if (!assemblyName)
				return std::string();
			const char* assemblyNameStr = monoManager.GetAssemblyNameName(assemblyName);
			return Create(assemblyNameStr, monoManager.GetClassNamespace(klass), monoManager.GetClassName(klass));
		}

		inline void Analysis(std::string signature, std::string& assembly, std::string& nameSpace, std::string& name)
		{
			assembly = signature.substr(signature.find("(") + 1, signature.find(")") - signature.find("(") - 1);
			signature = signature.substr(signature.find(")") + 1);
			nameSpace = signature.find(".") == std::string::npos ? "" : signature.substr(0, signature.rfind("."));
			name = signature.substr(signature.rfind(".") + 1);
		}
	}

	namespace Method
	{
		inline void Analysis(std::string signature, std::string& returnKlass, std::string& name, std::vector<std::string>& parameters)
		{
			returnKlass = signature.substr(0, signature.find(" "));
			signature = signature.substr(signature.find(" ") + 1);
			name = signature.substr(0, signature.find("("));
			signature = signature.substr(signature.find("(") + 1);
			if (signature.find(")") == std::string::npos)
				return;
			signature = signature.substr(0, signature.find(")"));

			if (signature.find("MPA_") != std::string::npos)
			{
				int index = std::stoi(signature.substr(signature.find("MPA_") + 4));
				for (int i = 0; i < index; i++)
				{
					parameters.push_back("AUTO");
				}
				return;
			}

			if (signature.size() <= 0)
			{
				parameters = std::vector<std::string>();
				return;
			}

			while (signature.find(",") != std::string::npos)
			{
				parameters.push_back(signature.substr(0, signature.find(",")));
				signature = signature.substr(signature.find(",") + 2);
			}
			parameters.push_back(signature);
		}

		inline std::string Create(MonoMethod* method, MonoManager monoManager)
		{
			std::string signature = monoManager.GetTypeName(monoManager.GetMethodReturnType(method)) + std::string(" ") + monoManager.GetMethodName(method) + "(";

			int paramCount = monoManager.GetMethodParamCount(method);
			MonoType* param = nullptr;
			void* iterator = nullptr;
			while ((param = monoManager.GetMethodParams(method, &iterator)) != nullptr)
			{
				signature += monoManager.GetTypeName(param) + std::string(", ");;
			}

			if (paramCount > 0)
			{
				signature = signature.substr(0, signature.size() - 2);
			}
			return signature + ")";
		}
	}
}

namespace ConfusedTranslate
{
	struct Klass
	{
		std::string assembly;
		std::string nameSpace;
		std::string originalName;
		std::string confusedName;
	};

	struct Method
	{
		Klass klass;
		std::string originalName;
		std::string confusedName;
	};

	inline std::vector<Klass> klass = std::vector<Klass>();

	inline std::vector<Method> method = std::vector<Method>();

	inline std::string RestoreKlass(std::string signature)
	{
		std::string assembly, nameSpace, name;
		Signature::Class::Analysis(signature, assembly, nameSpace, name);
		for (auto& k : klass)
		{
			if (k.assembly.compare(assembly) == 0 && k.nameSpace.compare(nameSpace) == 0 && k.originalName.compare(name) == 0)
				return Signature::Class::Create(k.assembly, k.nameSpace, k.confusedName);
		}
		return signature;
	}

	inline std::string RestoreMethod(std::string klassSignature, std::string methodName)
	{
		std::string assembly, nameSpace, name;
		Signature::Class::Analysis(klassSignature, assembly, nameSpace, name);
		for (auto& m : method)
		{
			if (m.klass.assembly.compare(assembly) == 0 && m.klass.nameSpace.compare(nameSpace) == 0 && (m.klass.confusedName.compare(name) == 0 || m.klass.originalName.compare(name) == 0) && m.originalName.compare(methodName) == 0)
				return m.confusedName;
		}
		return methodName;
	}
}

class NaResolver
{
public:
	struct Config
	{
		bool enableLogger = false;
		bool attachedThread = true;

		struct LoggerConfig
		{
			void (*fatal)(std::string, ...);
			void (*info)(std::string, ...);
			void (*debug)(std::string, ...);
			void (*error)(std::string, ...);
		} logger;
	};

	MonoManager monoManager;
	MonoDomain* domain;
	MonoThread* attachedThread;
	std::unordered_map<std::string, MonoAssembly*> assemblies;
	std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<std::string, MonoClass*>>> classes;

	inline NaResolver();
	inline bool Setup(Config config = NaResolver::Config());
	inline void Destroy();
	inline MonoClass* GetClassEx(std::string assembly, std::string nameSpace, std::string name);
	inline MonoClass* GetClass(std::string signature);
	inline MonoMethodPointer GetMethod(MonoClass* klass, std::string signature);
	inline MonoClassField* GetField(MonoClass* klass, std::string name);
	inline MonoType* GetType(std::string signature);
	inline MonoType* GetType(MonoClass* klass);
	inline std::string StringConvert(MonoString* string);

private:
	inline bool ClassExistsInCache(std::string assembly, std::string nameSpace, std::string signature);
	inline MonoAssembly* GetAssembly(std::string name);
	inline bool MethodVerifyParams(MonoClassField* method, std::vector<std::string> parameters);
	void (*LogFatal)(std::string, ...);
	void (*LogInfo)(std::string, ...);
	void (*LogDebug)(std::string, ...);
	void (*LogError)(std::string, ...);
};

inline NaResolver* MonoResolver = new NaResolver();

NaResolver::NaResolver()
{
	domain = nullptr;
	assemblies = std::unordered_map<std::string, MonoAssembly*>();
	classes = std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<std::string, MonoClass*>>>();
}

inline bool NaResolver::Setup(Config config)
{
	LogFatal = config.logger.fatal;
	LogError = config.logger.error;
	LogInfo = config.logger.info;
	LogDebug = config.logger.debug;
	if (!config.enableLogger)
	{
		LogFatal = LogInfo = LogDebug = LogError = (decltype(LogFatal))([](std::string, ...) -> void {});
	}

	try
	{
		monoManager.ImportMethods();
	}
	catch (const std::exception& e)
	{
		LogFatal("[NaResolver] Failed to import il2cpp methods: %s", e.what());
		return false;
	}

	if (domain = monoManager.GetRootDomain(), domain == nullptr)
	{
		LogFatal("[NaResolver] Domain get failed.");
		return false;
	}

	if (config.attachedThread)
	{
		attachedThread = monoManager.AttachThread(domain);
	}
	LogInfo("[NaResolver] Setup success.");
	return true;
}

inline void NaResolver::Destroy()
{
	if (attachedThread != nullptr)
	{
		monoManager.DetachThread(attachedThread);
		attachedThread = nullptr;
	}
	domain = nullptr;
	assemblies.clear();
	classes.clear();

	LogInfo("[NaResolver] Destroy success.");
}

inline MonoClass* NaResolver::GetClassEx(std::string _assembly, std::string _nameSpace, std::string _name)
{
	std::string assembly = _assembly, nameSpace = _nameSpace, name = _name;
	std::string signature = Signature::Class::Create(assembly, nameSpace, name);
	if (nameSpace.compare("") == 0)
	{
		nameSpace = "__NO_NAMESPACE__";
	}

	if (ClassExistsInCache(assembly, nameSpace, signature))
	{
		return classes[assembly][nameSpace][signature];
	}
	Signature::Class::Analysis(ConfusedTranslate::RestoreKlass(signature), assembly, nameSpace, name);

	MonoAssembly* pAssembly = GetAssembly(assembly);
	if (pAssembly == nullptr)
	{
		LogError("[NaResolver] Get assembly failed (%s).", assembly.c_str());
		return nullptr;
	}

	MonoImage* pImage = monoManager.GetAssemblyImage(pAssembly);
	if (!pImage)
	{
		LogError("[NaResolver] pImage is null for %s.", signature.c_str());
		return nullptr;
	}

	MonoClass* pClass = monoManager.GetClassFromName(pImage, nameSpace.c_str(), name.c_str());
	if (!pClass)
	{
		LogError("[NaResolver] pClass is null for %s.", signature.c_str());
		return nullptr;
	}
	if (classes.find(assembly) == classes.end())
	{
		classes.insert(std::make_pair(assembly, std::unordered_map<std::string, std::unordered_map<std::string, MonoClass*>>()));
	}
	if (nameSpace.compare("") == 0)
	{
		nameSpace = "__NO_NAMESPACE__";
	}
	if (classes[assembly].find(nameSpace) == classes[assembly].end())
	{
		classes[assembly].insert(std::make_pair(nameSpace, std::unordered_map<std::string, MonoClass*>()));
	}
	classes[assembly][nameSpace].insert(std::make_pair(signature, pClass));
	LogInfo("[NaResolver] Find class: %s", signature.c_str());
	return pClass;
}

inline MonoClass* NaResolver::GetClass(std::string signature)
{
	std::string assembly, nameSpace, name;
	Signature::Class::Analysis(ConfusedTranslate::RestoreKlass(signature), assembly, nameSpace, name);
	return GetClassEx(assembly, nameSpace, name);
}

inline MonoMethodPointer NaResolver::GetMethod(MonoClass* klass, std::string signature)
{
	if (klass == nullptr)
	{
		return nullptr;
	}
	std::string name = "";
	std::string returnType = "";
	std::vector<std::string> parameters = std::vector<std::string>();
	Signature::Method::Analysis(signature, returnType, name, parameters);
	name = ConfusedTranslate::RestoreMethod(Signature::Class::Create(klass, monoManager), name);

	MonoMethod* method = nullptr;
	void* iterator = nullptr;

	while ((method = monoManager.GetClassMethods(klass, &iterator)) != nullptr)
	{
		std::string methodName = monoManager.GetMethodName(method);
		if (methodName.compare(name) != 0 && name.compare("AUTO") != 0)
			continue;
		std::string returnTypeName = monoManager.GetTypeName(monoManager.GetMethodReturnType(method));
		if (returnTypeName.compare(returnType) != 0 && returnType.compare("AUTO") != 0)
			continue;
		if (!MethodVerifyParams(method, parameters))
			continue;
		LogInfo("[NaResolver] Find method: %s", signature.c_str());
		return monoManager.CompileMethod(method);
	}
	LogFatal("[NaResolver] Could not find the method: %s", signature.c_str());
	return nullptr;
}

inline MonoClassField* NaResolver::GetField(MonoClass* klass, std::string name)
{
	if (klass == nullptr)
	{
		return nullptr;
	}
	MonoClassField* field = nullptr;
	void* iterator = nullptr;

	while ((field = monoManager.GetClassFields(klass, &iterator)) != nullptr)
	{
		std::string fieldName = monoManager.GetFieldName(field);
		if (fieldName.compare(name) != 0)
			continue;
		LogInfo("[NaResolver] Find field: %s", name.c_str());
		return const_cast<MonoClassField*>(field);
	}
}

inline MonoType* NaResolver::GetType(std::string signature)
{
	std::string assembly, nameSpace, name;
	Signature::Class::Analysis(ConfusedTranslate::RestoreKlass(signature), assembly, nameSpace, name);
	MonoClass* klass = GetClassEx(assembly, nameSpace, name);
	if (klass == nullptr)
	{
		return nullptr;
	}
	return monoManager.GetClassType(klass);
}

inline MonoType* NaResolver::GetType(MonoClass* klass)
{
	if (klass == nullptr)
	{
		return nullptr;
	}
	return monoManager.GetClassType(klass);
}

inline std::string NaResolver::StringConvert(MonoString* string)
{
	if (!string)
	{
		return std::string();
	}
	char16_t* chars = (char16_t*)monoManager.GetStringChars(string);
	int len = (int)monoManager.GetStringLength(string);
	int size = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)chars, len, NULL, 0, NULL, NULL);
	char* buffer = new char[size + 1];
	WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)chars, len, buffer, size, NULL, NULL);
	buffer[size] = '\0';
	std::string result = std::string(buffer);
	delete[] buffer;
	return result;
}

inline bool NaResolver::ClassExistsInCache(std::string assembly, std::string nameSpace, std::string signature)
{
	if (classes.find(assembly) == classes.end())
	{
		return false;
	}
	if (classes[assembly].find(nameSpace) == classes[assembly].end())
	{
		return false;
	}
	return classes[assembly][nameSpace].find(signature) != classes[assembly][nameSpace].end();
}

inline MonoAssembly* NaResolver::GetAssembly(std::string name)
{
	if (assemblies.find(name) != assemblies.end())
	{
		return assemblies[name];
	}
	MonoAssembly* assembly = monoManager.OpenDomainAssembly(domain, name.c_str());
	if (!assembly)
	{
		return nullptr;
	}
	assemblies[name] = assembly;
	return assembly;
}

inline bool NaResolver::MethodVerifyParams(MonoMethod* method, std::vector<std::string> parameters)
{
	uint32_t methodParamCount = monoManager.GetMethodParamCount(method);
	if (methodParamCount != parameters.size())
	{
		return false;
	}

	MonoType* methodParam = nullptr;
	void* iterator = nullptr;
	uint32_t i = 0;
	while ((methodParam = monoManager.GetMethodParams(method, &iterator)) != nullptr)
	{
		if (parameters[i].compare("AUTO") == 0)
		{
			i++;
			continue;
		}
		std::string parameterName = monoManager.GetTypeName(methodParam);
		if (parameterName.compare(parameters[i]) != 0)
		{
			return false;
		}
		i++;
	}
	return true;
}

#define STATIC_AREA_OFFSET (sizeof(void *) == 8 ? 0xB8 : 0xC5)
#define CLASS(assembly, namespaze, klass) \
	static struct Il2CppClass *ThisClass() { return Il2CppResolver->GetClassEx(assembly, namespaze, klass); }
#define MEMBER(klass, name, offset) \
	struct                          \
	{                               \
		char __pad__##name[offset]; \
		klass name;                 \
	}
#define STATIC_MEMBER(klass, name, offset)                                                                                                                 \
	static klass get_##name() { return *reinterpret_cast<klass *>(*reinterpret_cast<uintptr_t *>((uintptr_t)ThisClass() + STATIC_AREA_OFFSET) + offset); } \
	static void set_##name(klass value) { *reinterpret_cast<klass *>(*reinterpret_cast<uintptr_t *>((uintptr_t)ThisClass() + STATIC_AREA_OFFSET) + offset) = value; }
#define METHOD(returnType, parameters, signature) static auto function = (returnType(*) parameters)(Il2CppResolver->GetMethod(ThisClass(), signature));

#endif