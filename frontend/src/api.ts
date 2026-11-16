// Единый адрес API. В production задаётся через VITE_API_URL и должен быть https://
// (доверенный путь, слайд 12; Конституция РФ ст. 23, 149-ФЗ).
export const API_URL: string = import.meta.env.VITE_API_URL ?? 'http://localhost:5000'

if (import.meta.env.PROD && !API_URL.startsWith('https://')) {
    throw new Error('VITE_API_URL должен использовать https:// в production-сборке')
}
