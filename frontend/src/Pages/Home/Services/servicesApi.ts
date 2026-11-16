import { Photos } from '../../../../Photos'
import { API_URL } from '../../../api'

export interface Service {
    id: number
    name: string
    description: string
    image: string
    category: string
}

export async function getServices(category: string): Promise<Service[]> {
    const url =
        category === 'all'
            ? `${API_URL}/services`
            : `${API_URL}/services?category=${category}`

    const res = await fetch(url)
    if (!res.ok) throw new Error('Failed to load services')
    return res.json()
}

export function serviceImage(name: string): string {
    return Photos.Services[name as keyof typeof Photos.Services]
        ?? Photos.Residential;
}