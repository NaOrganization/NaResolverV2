#include <Windows.h>
#include "../NaResolver.h"

#define LOGGER_FUNCTION(level) ([](std::string m, ...)->void\
			{\
			m = #level " " + m + "\n";\
			va_list args;\
			va_start(args, m);\
			vprintf(m.c_str(), args);\
			va_end(args);\
			})

int WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		AllocConsole();
		freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
		NaResolver::Config config;
		config.enableLogger = true;
		config.logger.debug = LOGGER_FUNCTION([DEBUG]);
		config.logger.info = LOGGER_FUNCTION([INFO]);
		config.logger.error = LOGGER_FUNCTION([ERROR]);
		config.logger.fatal = LOGGER_FUNCTION([FATAL]);

		if (!MonoResolver->Setup(config))
			printf("Failed to setup I2Hrame!\n");
		MonoClass *klass = MonoResolver->GetClassEx("UnityEngine.CoreModule", "UnityEngine", "GameObject");
		printf("(Il2CppResolver->GetClassEx) Class: %p\n", klass);
		klass = MonoResolver->GetClass("(UnityEngine.CoreModule)UnityEngine.GameObject");
		printf("(Il2CppResolver->GetClass) Class: %p\n", klass);
		MonoMethodPointer method = MonoResolver->GetMethod(klass, "UnityEngine.Transform get_transform()");
		printf("(Il2CppResolver->GetMethod) Method: %p\n", method);

		klass = MonoResolver->GetClass("(UnityEngine.CoreModule)UnityEngine.GameObjct");
		printf("(Error Demonstration) Class: %p\n", klass);
		
		MonoResolver->Destroy();
		free(MonoResolver);

		FreeConsole();
	}
	return TRUE; // Successful DLL_PROCESS_ATTACH.
}