//**************************************//
// Hi NaResolver			//
// Author: MidTerm                   	//
// Version: v1.0.0                      //
// Branch: Mono				//
// License: MIT                         //
//**************************************//

#if !_HAS_CXX17
#pragma message("The contents of NaResolver are available only with C++17 or later.")
#endif

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
typedef void* MonoMethodPointer;
typedef wchar_t MonoChar;

class MonoManager
{
public:
	HMODULE assemblyModule;
	std::unordered_map<std::string, void*> monoMethodMap =
	{
		{ "mono_get_root_domain", nullptr },
		{ "mono_domain_assembly_open", nullptr },
		{ "mono_type_get_name", nullptr },
		{ "mono_thread_attach", nullptr },
		{ "mono_string_new", nullptr },
		{ "mono_string_to_utf8", nullptr },
		{ "mono_thread_detach", nullptr },
		{ "mono_class_get_methods", nullptr },
		{ "mono_class_from_name", nullptr },
		{ "mono_assembly_get_image", nullptr },
		{ "mono_method_get_name", nullptr },
		{ "mono_method_signature", nullptr },
		{ "mono_signature_get_return_type", nullptr },
		{ "mono_signature_get_param_count", nullptr },
		{ "mono_signature_get_params", nullptr },
		{ "mono_class_get_name", nullptr },
		{ "mono_class_get_namespace", nullptr },
		{ "mono_class_get_image", nullptr },
		{ "mono_image_get_assembly", nullptr },
		{ "mono_assembly_get_name", nullptr },
		{ "mono_assembly_name_get_name", nullptr },
		{ "mono_compile_method", nullptr },
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

	inline MonoDomain* GetDomain() { return ((MonoDomain * (*)(void))monoMethodMap["mono_get_root_domain"])(); }
	inline MonoAssembly* OpenDomainAssembly(MonoDomain* domain, const char* name) { return ((MonoAssembly * (*)(MonoDomain*, const char*))monoMethodMap["mono_domain_assembly_open"])(domain, name); }
	inline char* GetTypeName(MonoType* type) { return ((char* (*)(MonoType*))monoMethodMap["mono_type_get_name"])(type); }
	inline MonoString* NewString(MonoDomain* domain, const char* string) { return ((MonoString * (*)(MonoDomain*, const char*))monoMethodMap["mono_string_new"])(domain, string); }
	inline char* StringToUTF8(MonoString* string) { return ((char* (*)(MonoString*))monoMethodMap["mono_string_to_utf8"])(string); }
	inline MonoThread* AttachThread(MonoDomain* domain) { return ((MonoThread * (*)(MonoDomain*))monoMethodMap["mono_thread_attach"])(domain); }
	inline void DetachThread(MonoThread* thread) { ((void(*)(MonoThread*))monoMethodMap["mono_thread_detach"])(thread); }
	inline MonoMethod* GetClassMethods(MonoClass* klass, void** iter) { return ((MonoMethod * (*)(MonoClass*, void**))monoMethodMap["mono_class_get_methods"])(klass, iter); }
	inline MonoClass* GetClassFromName(MonoImage* image, const char* nameSpace, const char* name) { return ((MonoClass * (*)(MonoImage*, const char*, const char*))monoMethodMap["mono_class_from_name"])(image, nameSpace, name); }
	inline MonoImage* GetAssemblyImage(MonoAssembly* assembly) { return ((MonoImage * (*)(const MonoAssembly*))monoMethodMap["mono_assembly_get_image"])(assembly); }
	inline const char* GetMethodName(MonoMethod* method) { return ((const char* (*)(MonoMethod*))monoMethodMap["mono_method_get_name"])(method); }
	inline MonoMethodSignature* GetMethodSignature(MonoMethod* method) { return ((MonoMethodSignature * (*)(MonoMethod*))monoMethodMap["mono_method_signature"])(method); }
	inline MonoType* GetMethodReturnType(MonoMethodSignature* signature) { return ((MonoType * (*)(MonoMethodSignature*))monoMethodMap["mono_signature_get_return_type"])(signature); }
	inline uint32_t GetMethodParamCount(MonoMethodSignature* signature) { return ((uint32_t(*)(MonoMethodSignature*))monoMethodMap["mono_signature_get_param_count"])(signature); }
	inline MonoType* GetMethodParam(MonoMethodSignature* signature, void** iter) { return ((MonoType * (*)(MonoMethodSignature*, void**))monoMethodMap["mono_signature_get_params"])(signature, iter); }
	inline const char* GetClassName(MonoClass* klass) { return ((const char* (*)(MonoClass*))monoMethodMap["mono_class_get_name"])(klass); }
	inline const char* GetClassNamespace(MonoClass* klass) { return ((const char* (*)(MonoClass*))monoMethodMap["mono_class_get_namespace"])(klass); }
	inline MonoImage* GetClassImage(MonoClass* klass) { return ((MonoImage * (*)(MonoClass*))monoMethodMap["mono_class_get_image"])(klass); }
	inline MonoAssembly* GetImageAssembly(MonoImage* image) { return ((MonoAssembly * (*)(MonoImage*))monoMethodMap["mono_image_get_assembly"])(image); }
	inline MonoAssemblyName* GetAssemblyName(MonoAssembly* assembly) { return ((MonoAssemblyName * (*)(MonoAssembly*))monoMethodMap["mono_assembly_get_name"])(assembly); }
	inline const char* GetAssemblyNameName(MonoAssemblyName* assemblyName) { return ((const char* (*)(MonoAssemblyName*))monoMethodMap["mono_assembly_name_get_name"])(assemblyName); }
	inline void* CompileMethod(MonoMethod* method) { return ((void* (*)(MonoMethod*))monoMethodMap["mono_compile_method"])(method); }
	
	inline MonoType* GetMethodReturnTypeEx(MonoMethod* method)
	{
		MonoMethodSignature* signature = GetMethodSignature(method);
		if (signature == nullptr)
		{
			return nullptr;
		}
		return GetMethodReturnType(signature);
	}
	inline uint32_t GetMethodParamCountEx(MonoMethod* method)
	{
		MonoMethodSignature* signature = GetMethodSignature(method);
		if (signature == nullptr)
		{
			return 0;
		}
		return GetMethodParamCount(signature);
	}
	inline MonoType* GetMethodParamEx(MonoMethod* method, void** iter)
	{
		MonoMethodSignature* signature = GetMethodSignature(method);
		if (signature == nullptr)
		{
			return nullptr;
		}
		return GetMethodParam(signature, iter);
	}
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

		inline void Analysis(std::string signature, std::string* assembly, std::string* nameSpace, std::string* name)
		{
			*assembly = signature.substr(signature.find("(") + 1, signature.find(")") - signature.find("(") - 1);
			signature = signature.substr(signature.find(")") + 1);
			*nameSpace = signature.find(".") == std::string::npos ? "" : signature.substr(0, signature.rfind("."));
			*name = signature.substr(signature.rfind(".") + 1);
		}
	}

	namespace Method
	{
		inline void Analysis(std::string signature, std::string* returnKlass, std::string* name, std::vector<std::string>* parameters)
		{
			*returnKlass = signature.substr(0, signature.find(" "));
			signature = signature.substr(signature.find(" ") + 1);
			*name = signature.substr(0, signature.find("("));
			signature = signature.substr(signature.find("(") + 1);
			if (signature.find(")") == std::string::npos)
				return;
			signature = signature.substr(0, signature.find(")"));

			if (signature.find("MPA_") != std::string::npos)
			{
				int index = std::stoi(signature.substr(signature.find("MPA_") + 4));
				for (int i = 0; i < index; i++)
				{
					parameters->push_back("AUTO");
				}
				return;
			}

			if (signature.size() <= 0)
			{
				parameters = new std::vector<std::string>();
				return;
			}

			while (signature.find(",") != std::string::npos)
			{
				parameters->push_back(signature.substr(0, signature.find(",")));
				signature = signature.substr(signature.find(",") + 2);
			}
			parameters->push_back(signature);
		}

		inline std::string Create(MonoMethod* method, MonoManager monoManager)
		{
			std::string signature = monoManager.GetTypeName(monoManager.GetMethodReturnTypeEx(method)) + std::string(" ") + monoManager.GetMethodName(method) + "(";

			int paramCount = monoManager.GetMethodParamCountEx(method);
			for (int i = 0; i < paramCount; i++)
			{
				signature += monoManager.GetTypeName(monoManager.GetMethodReturnTypeEx(method)) + std::string(", ");
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
		Signature::Class::Analysis(signature, &assembly, &nameSpace, &name);
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
		Signature::Class::Analysis(klassSignature, &assembly, &nameSpace, &name);
		for (auto& m : method)
		{
			if (m.klass.assembly.compare(assembly) == 0 && m.klass.nameSpace.compare(nameSpace) == 0 && (m.klass.confusedName.compare(name) == 0 || m.klass.originalName.compare(name) == 0) && m.originalName.compare(methodName) == 0)
				return m.confusedName;
		}
		return methodName;
	}

	inline std::string ConvertKlass(std::string signature)
	{
		std::string assembly, nameSpace, name;
		Signature::Class::Analysis(signature, &assembly, &nameSpace, &name);
		for (auto& k : klass)
		{
			bool allMatch = k.assembly.compare(assembly) == 0 && k.nameSpace.compare(nameSpace) == 0 && k.confusedName.compare(name) == 0;
			if (allMatch)
				return Signature::Class::Create(k.assembly, k.nameSpace, k.originalName);
		}
		return signature;
	}
}

class NaResolver
{
public:
	struct Config
	{
		bool enableLogger = false;

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
	std::unordered_map<std::string, MonoType*> types;

	inline NaResolver();
	inline bool Setup(Config config);
	inline void Destroy();
	inline MonoClass* GetClassEx(std::string assembly, std::string nameSpace, std::string name);
	inline MonoClass* GetClass(std::string signature);
	inline MonoMethodPointer GetMethod(MonoClass* klass, std::string signature);
	inline MonoType* GetType(std::string signature);
	inline MonoType* GetType(MonoClass* klass);
	inline std::string GetStringByMono(MonoString* string);
private:
	inline bool ClassExistsInCache(std::string assembly, std::string nameSpace, std::string name);
	inline MonoAssembly* GetAssembly(std::string name);
	inline bool MethodVerifyParams(MonoMethod* method, std::vector<std::string> parameters);
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
	types = std::unordered_map<std::string, MonoType*>();
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

	if (domain = monoManager.GetDomain(), domain == nullptr)
	{
		LogFatal("[NaResolver] Domain get failed.");
		return false;
	}

	attachedThread = monoManager.AttachThread(domain);
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
	types.clear();

	LogInfo("[NaResolver] Destroy success.");
}

inline MonoClass* NaResolver::GetClassEx(std::string _assembly, std::string _nameSpace, std::string _name)
{
	std::string assembly = _assembly, nameSpace = _nameSpace, name = _name;
	std::string signature = Signature::Class::Create(assembly, nameSpace, name);
	if (nameSpace.compare("") == 0)
		nameSpace = "__NO_NAMESPACE__";

	if (ClassExistsInCache(assembly, nameSpace, name))
		return classes[assembly][nameSpace][signature];

	Signature::Class::Analysis(ConfusedTranslate::RestoreKlass(signature), &assembly, &nameSpace, &name);

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
		nameSpace = "__NO_NAMESPACE__";
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
	Signature::Class::Analysis(ConfusedTranslate::RestoreKlass(signature), &assembly, &nameSpace, &name);
	return GetClassEx(assembly, nameSpace, name);
}

inline MonoMethodPointer NaResolver::GetMethod(MonoClass* klass, std::string signature)
{
	if (klass == nullptr)
		return nullptr;

	std::string name = "";
	std::string returnType = "";
	std::vector<std::string> parameters = std::vector<std::string>();
	Signature::Method::Analysis(signature, &returnType, &name, &parameters);
	name = ConfusedTranslate::RestoreMethod(Signature::Class::Create(klass, monoManager), name);

	void* iterator = nullptr;
	MonoMethod* method = nullptr;

	while ((method = monoManager.GetClassMethods(klass, &iterator)) != nullptr)
	{
		std::string methodName = monoManager.GetMethodName(method);
		if (methodName.compare(name) != 0 && name.compare("AUTO") != 0)
			continue;
		std::string returnTypeName = monoManager.GetTypeName(monoManager.GetMethodReturnTypeEx(method));
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

inline MonoType* NaResolver::GetType(std::string signature)
{
	if (types.find(signature) != types.end())
		return types[signature];
	static auto func = ((MonoType * (*)(MonoString * typeName, MonoMethod * method))
		GetMethod(GetClassEx("mscorlib", "System", "Type"), "System.Type GetType(System.String)"));
	MonoType* result = func(monoManager.NewString(domain, signature.c_str()), nullptr);
	if (!result)
	{
		LogError("[NaResolver] Could not find the type: %s", signature.c_str());
		return nullptr;
	}
	types[signature] = result;
	return result;
}

inline MonoType* NaResolver::GetType(MonoClass* klass)
{
	if (klass == nullptr)
		return nullptr;
	std::string signature = ConfusedTranslate::RestoreKlass(Signature::Class::Create(klass, monoManager));
	std::string assembly, nameSpace, name;
	Signature::Class::Analysis(signature, &assembly, &nameSpace, &name);
	std::string typeSignature = name + ", " + assembly;
	if (nameSpace.size() > 0)
		typeSignature = nameSpace + "." + typeSignature;
	return GetType(typeSignature);
}

inline std::string NaResolver::GetStringByMono(MonoString* string)
{
	if (!string)
	{
		return std::string();
	}

	return monoManager.StringToUTF8(string);
}

inline bool NaResolver::ClassExistsInCache(std::string assembly, std::string nameSpace, std::string name)
{
	if (classes.find(assembly) == classes.end())
	{
		return false;
	}
	if (classes[assembly].find(nameSpace) == classes[assembly].end())
	{
		return false;
	}
	return classes[assembly][nameSpace].find(name) != classes[assembly][nameSpace].end();
}

inline MonoAssembly* NaResolver::GetAssembly(std::string name)
{
	if (assemblies.find(name) != assemblies.end())
		return assemblies[name];
	MonoAssembly* assembly = monoManager.OpenDomainAssembly(domain, name.c_str());
	if (!assembly)
		return nullptr;
	assemblies[name] = assembly;
	return assembly;
}

inline bool NaResolver::MethodVerifyParams(MonoMethod* method, std::vector<std::string> parameters)
{
	uint32_t methodParamCount = monoManager.GetMethodParamCountEx(method);
	if (methodParamCount != parameters.size())
		return false;

	int index = 0;
	void* iterator = nullptr;
	MonoType* paramType = nullptr;
	while ((paramType = monoManager.GetMethodParamEx(method, &iterator)) != nullptr)
	{
		std::string paramTypeName = monoManager.GetTypeName(paramType);
		if (paramTypeName.compare("AUTO") == 0)
		{
			index++;
			continue;
		}
		if (paramTypeName.compare(parameters[index]) == 0)
			break;
		index++;
	}
	return true;
}

#define STATIC_AREA_OFFSET (sizeof(void *) == 8 ? 0xB8 : 0xC5)
#define CLASS(assembly, namespaze, klass) \
	static MonoClass *ThisClass() { return MonoResolver->GetClassEx(assembly, namespaze, klass); }
#define MEMBER(klass, name, offset) \
	struct                          \
	{                               \
		char __pad__##name[offset]; \
		klass name;                 \
	}
#define STATIC_MEMBER(klass, name, offset)                                                                                                                 \
	static klass get_##name() { return *reinterpret_cast<klass *>(*reinterpret_cast<uintptr_t *>((uintptr_t)ThisClass() + STATIC_AREA_OFFSET) + offset); } \
	static void set_##name(klass value) { *reinterpret_cast<klass *>(*reinterpret_cast<uintptr_t *>((uintptr_t)ThisClass() + STATIC_AREA_OFFSET) + offset) = value; }
#define METHOD(returnType, parameters, signature) static auto __fn = (returnType(*) parameters)(MonoResolver->GetMethod(ThisClass(), signature));
