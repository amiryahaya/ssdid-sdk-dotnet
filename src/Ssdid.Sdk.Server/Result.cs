namespace Ssdid.Sdk.Server;

public readonly struct Result<T>
{
    public T? Value { get; }
    public SsdidError? Error { get; }
    public bool IsSuccess => Error is null;

    private Result(T value) { Value = value; Error = null; }
    private Result(SsdidError error) { Value = default; Error = error; }

    public static implicit operator Result<T>(T value) => new(value);
    public static implicit operator Result<T>(SsdidError error) => new(error);

    public TResult Match<TResult>(Func<T, TResult> success, Func<SsdidError, TResult> failure) =>
        IsSuccess ? success(Value!) : failure(Error!);

    public async Task<TResult> Match<TResult>(Func<T, Task<TResult>> success, Func<SsdidError, Task<TResult>> failure) =>
        IsSuccess ? await success(Value!) : await failure(Error!);
}
