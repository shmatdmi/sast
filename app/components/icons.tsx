import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function IconBase({ size = 20, children, ...props }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      {children}
    </svg>
  );
}

export const ShieldIcon = (props: IconProps) => <IconBase {...props}><path d="M12 3 4.5 6v5.3c0 4.7 3.1 8.9 7.5 10.2 4.4-1.3 7.5-5.5 7.5-10.2V6L12 3Z"/><path d="m9 12 2 2 4-5"/></IconBase>;
export const UploadIcon = (props: IconProps) => <IconBase {...props}><path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M5 20h14"/></IconBase>;
export const ScanIcon = (props: IconProps) => <IconBase {...props}><path d="M4 7V4h3M17 4h3v3M20 17v3h-3M7 20H4v-3"/><path d="M7 12h10M12 7v10"/></IconBase>;
export const FileIcon = (props: IconProps) => <IconBase {...props}><path d="M6 2.8h7l5 5V21H6z"/><path d="M13 3v5h5M9 13h6M9 17h4"/></IconBase>;
export const CheckIcon = (props: IconProps) => <IconBase {...props}><path d="m5 12 4 4L19 6"/></IconBase>;
export const AlertIcon = (props: IconProps) => <IconBase {...props}><path d="M10.3 3.8 2.6 18a2 2 0 0 0 1.8 3h15.2a2 2 0 0 0 1.8-3L13.7 3.8a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/></IconBase>;
export const DownloadIcon = (props: IconProps) => <IconBase {...props}><path d="M12 3v12m0 0 4-4m-4 4-4-4M5 21h14"/></IconBase>;
export const ChevronIcon = (props: IconProps) => <IconBase {...props}><path d="m8 10 4 4 4-4"/></IconBase>;
export const CodeIcon = (props: IconProps) => <IconBase {...props}><path d="m8 9-3 3 3 3M16 9l3 3-3 3M14 5l-4 14"/></IconBase>;
export const LockIcon = (props: IconProps) => <IconBase {...props}><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></IconBase>;
export const CopyIcon = (props: IconProps) => <IconBase {...props}><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></IconBase>;
export const CloseIcon = (props: IconProps) => <IconBase {...props}><path d="m6 6 12 12M18 6 6 18"/></IconBase>;
export const UserIcon = (props: IconProps) => <IconBase {...props}><circle cx="12" cy="8" r="4"/><path d="M4.5 21a7.5 7.5 0 0 1 15 0"/></IconBase>;
