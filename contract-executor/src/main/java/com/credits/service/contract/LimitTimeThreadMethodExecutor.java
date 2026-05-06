package com.credits.service.contract;

import com.credits.general.thrift.generated.Variant;
import com.credits.pojo.MethodData;
import exception.ContractExecutorException;
import pojo.session.InvokeMethodSession;

import java.util.List;
import java.util.stream.Collectors;

import static com.credits.general.util.variant.VariantConverter.toVariant;
import static com.credits.utils.ContractExecutorServiceUtils.getMethodArgumentsValuesByNameAndParams;
import static java.util.Arrays.stream;
import static org.apache.commons.lang3.exception.ExceptionUtils.getRootCauseMessage;

class LimitTimeThreadMethodExecutor extends LimitedExecutionMethod<Variant> {
    private final InvokeMethodSession session;
    private Object instance;
    private final ClassLoader classLoader;

    public LimitTimeThreadMethodExecutor(InvokeMethodSession session, Object contractInstance) {
        super(session);
        this.session = session;
        this.instance = contractInstance;
        this.classLoader = instance.getClass().getClassLoader();
    }

    public List<MethodResult> executeIntoLimitTimeThread() {
        return session.paramsTable.length < 2
                ? invokeSingleMethod()
                : invokeMultipleMethod();
    }

    private List<MethodResult> invokeSingleMethod() {
        return List.of(prepareResult(invokeIntoLimitTimeThread(session.paramsTable[0])));
    }

    private List<MethodResult> invokeMultipleMethod() {
        // State is deserialized once in ContractExecutorServiceImpl.executeSmartContract;
        // all N invocations share that single instance. Eliminates O(N) deserialize
        // cost on batch reads (e.g. balanceOf with 1000+ addresses) which previously
        // OOM'd the JVM by allocating ~N × stateSize bytes of churn.
        //
        // Semantic note: for getter methods (no mutation) the result is identical to
        // the previous behavior. For write methods, mutations now ACCUMULATE across
        // invocations within the batch instead of being independent. The persisted
        // state is still the final instance, which matches the old "last wins"
        // behavior for the saved state.
        final var results = stream(session.paramsTable)
                .map(params -> prepareResult(invokeIntoLimitTimeThread(params)))
                .collect(Collectors.toList());
        session.usedContracts.get(session.contractAddress).setInstance(instance);
        return results;
    }

    private Variant invokeIntoLimitTimeThread(Variant... params) {
        final var methodData = findInvokedMethodIntoContract(params);
        final var method = methodData.method;
        final var returnTypeName = method.getReturnType().getTypeName();
        return runForLimitTime(() -> toVariant(returnTypeName, method.invoke(instance, methodData.argValues)));
    }

    private MethodData findInvokedMethodIntoContract(Variant[] params) {
        try {
            return getMethodArgumentsValuesByNameAndParams(instance.getClass(), session.methodName, params, classLoader);
        } catch (ClassNotFoundException e) {
            throw new ContractExecutorException(getRootCauseMessage(e));
        }
    }
}
