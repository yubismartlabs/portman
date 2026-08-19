import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

export function Button({ className, variant = "default", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "default" | "ghost" | "danger" }) {
  const variants = { default: "bg-indigo-500 hover:bg-indigo-400 text-white", ghost: "bg-transparent hover:bg-white/6 text-slate-300", danger: "bg-rose-500 hover:bg-rose-400 text-white" };
  return <button className={cn("inline-flex h-9 items-center justify-center gap-2 rounded-lg px-3 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-45", variants[variant], className)} {...props} />;
}

export function Modal({ open, onOpenChange, title, children }: { open: boolean; onOpenChange: (value: boolean) => void; title: string; children: React.ReactNode }) {
  return <Dialog.Root open={open} onOpenChange={onOpenChange}><Dialog.Portal><Dialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm" /><Dialog.Content className="surface fixed left-1/2 top-1/2 w-[470px] -translate-x-1/2 -translate-y-1/2 rounded-2xl p-6 outline-none"><div className="mb-4 flex items-center justify-between"><Dialog.Title className="text-lg font-semibold">{title}</Dialog.Title><Dialog.Close asChild><Button variant="ghost" className="h-8 w-8 p-0"><X size={16}/></Button></Dialog.Close></div>{children}</Dialog.Content></Dialog.Portal></Dialog.Root>;
}
